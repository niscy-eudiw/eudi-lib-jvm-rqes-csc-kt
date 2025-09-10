/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.podofomanager

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.podofo.android.PoDoFoWrapper
import eu.europa.ec.eudi.rqes.ConformanceLevel
import eu.europa.ec.eudi.rqes.CredentialCertificate
import eu.europa.ec.eudi.rqes.CrlRequest
import eu.europa.ec.eudi.rqes.Digest
import eu.europa.ec.eudi.rqes.DocumentDigest
import eu.europa.ec.eudi.rqes.DocumentDigestList
import eu.europa.ec.eudi.rqes.DocumentToSign
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.OcspRequest
import eu.europa.ec.eudi.rqes.RevocationServiceImpl
import eu.europa.ec.eudi.rqes.TimestampRequestTO
import eu.europa.ec.eudi.rqes.TimestampResponseTO
import eu.europa.ec.eudi.rqes.TimestampServiceImpl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant

class PodofoManager {
    private var podofoSessions by mutableStateOf<List<PodofoSession>>(emptyList())

    suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
        tsaUrl: String,
    ): DocumentDigestList {
        try {
            podofoSessions = emptyList()
            val endEntityCertificate = credentialCertificate.rawCertificates.first()
            val certificateChain = credentialCertificate.rawCertificates.drop(1)

            val hashes = mutableListOf<String>()
            var c = 1

            validateTsaUrlRequirement(documents, tsaUrl)

            for (doc in documents) {
                try {
                    val podofoWrapper = PoDoFoWrapper(
                        doc.conformanceLevel.name,
                        hashAlgorithmOID.value,
                        doc.documentInputPath,
                        doc.documentOutputPath,
                        endEntityCertificate,
                        certificateChain.toTypedArray(),
                    )

                    val session = PodofoSession(
                        id = c.toString(),
                        session = podofoWrapper,
                        conformanceLevel = doc.conformanceLevel,
                        endCertificate = endEntityCertificate,
                        chainCertificates = certificateChain,
                    )
                    c++

                    podofoWrapper.calculateHash()?.let { hash ->
                        hashes += hash
                        podofoSessions = podofoSessions + session
                    } ?: throw IllegalStateException("Failed to calculate hash for document: ${doc.documentInputPath}")
                } catch (_: Exception) {
                    error("Failed to calculate hash for ${doc.documentOutputPath}")
                }
            }

            if (hashes.size != documents.size) {
                error("Internal error: got ${hashes.size} hashes for ${documents.size} documents")
            }

            val digestEntries = hashes.mapIndexed { idx, rawHash ->
                DocumentDigest(
                    hash = Digest(rawHash),
                    label = documents[idx].label,
                )
            }

            return DocumentDigestList(
                documentDigests = digestEntries,
                hashAlgorithmOID = HashAlgorithmOID(hashAlgorithmOID.value),
                hashCalculationTime = Instant.now(),
            )
        } catch (e: Exception) {
            throw e
        }
    }

    suspend fun createSignedDocuments(signatures: List<String>, tsaUrl: String?, includeRevocationInfo: Boolean) = withContext(
        Dispatchers.IO,
    ) {
        try {
            check(signatures.size == podofoSessions.size) {
                "Signatures count (${signatures.size}) does not match session count (${podofoSessions.size})"
            }

            podofoSessions.forEachIndexed { index, sessionWrapper ->
                val signedHash = signatures[index]
                sessionWrapper.session.printState()

                when (sessionWrapper.conformanceLevel) {
                    ConformanceLevel.ADES_B_B -> {
                        handleAdesB_B(sessionWrapper, signedHash)
                    }
                    ConformanceLevel.ADES_B_T -> {
                        require(
                            !tsaUrl.isNullOrEmpty(),
                        ) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_T(sessionWrapper, signedHash, tsaUrl)
                    }
                    ConformanceLevel.ADES_B_LT -> {
                        require(
                            !tsaUrl.isNullOrEmpty(),
                        ) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LT(sessionWrapper, signedHash, tsaUrl, includeRevocationInfo)
                    }
                    ConformanceLevel.ADES_B_LTA -> {
                        require(
                            !tsaUrl.isNullOrEmpty(),
                        ) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LTA(sessionWrapper, signedHash, tsaUrl, includeRevocationInfo)
                    }
                    else -> throw IllegalArgumentException("Unknown or unsupported conformance level")
                }
            }
        } finally {
            podofoSessions = emptyList()
        }
    }

    private fun handleAdesB_B(sessionWrapper: PodofoSession, signedHash: String) {
        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            "",
            mutableListOf(),
            mutableListOf(),
            mutableListOf(),
        )
    }

    private suspend fun handleAdesB_T(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        val response = requestTimestamp(signedHash, tsaUrl)

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            response.base64Tsr,
            mutableListOf(),
            mutableListOf(),
            mutableListOf(),
        )
    }

    private suspend fun handleAdesB_LT(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String, includeRevocationInfo: Boolean) {
        val timestampAndRevocationData = addTimestampAndRevocationInfo(
            sessionWrapper,
            signedHash,
            tsaUrl,
            includeRevocationInfo,
        )

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            timestampAndRevocationData.tsResponse.base64Tsr,
            timestampAndRevocationData.validationCertificates,
            timestampAndRevocationData.validationCrls,
            timestampAndRevocationData.validationOCSPs,
        )
    }

    private suspend fun handleAdesB_LTA(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String, includeRevocationInfo: Boolean) {
        val timestampAndRevocationData = addTimestampAndRevocationInfo(
            sessionWrapper,
            signedHash,
            tsaUrl,
            includeRevocationInfo,
        )

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            timestampAndRevocationData.tsResponse.base64Tsr,
            timestampAndRevocationData.validationCertificates,
            timestampAndRevocationData.validationCrls,
            timestampAndRevocationData.validationOCSPs,
        )

        val ltaRawHash = sessionWrapper.session.beginSigningLTA()
        if (ltaRawHash != null) {
            val tsLtaResponse = requestDocTimestamp(ltaRawHash, tsaUrl)

            val validationLTACertificates: MutableList<String> = mutableListOf()
            val validationLTACrls: MutableList<String> = mutableListOf()
            val validationLTAOCSPs: MutableList<String> = mutableListOf()

            try {
                val tsaLTASignerCert =
                    sessionWrapper.session.extractSignerCertFromTSR(tsLtaResponse.base64Tsr)
                validationLTACertificates.add(tsaLTASignerCert)

                val tsaLTAIssuerCert =
                    sessionWrapper.session.extractIssuerCertFromTSR(tsLtaResponse.base64Tsr)
                validationLTACertificates.add(tsaLTAIssuerCert)

                if (includeRevocationInfo) {
                    val base64LTAOcspResponse = fetchOcspResponse(
                        sessionWrapper,
                        tsLtaResponse.base64Tsr,
                    )
                    validationLTAOCSPs.add(base64LTAOcspResponse)

                    val crlLTAUrls = mutableSetOf<String>()
                    sessionWrapper.session.getCrlFromCertificate(tsaLTASignerCert)
                        ?.let { crlSignerLTAUrl ->
                            crlLTAUrls.add(crlSignerLTAUrl)
                        }
                    val crls = fetchCrlDataFromUrls(crlLTAUrls.toList())
                    validationLTACrls.addAll(crls)
                }
            } catch (_: Exception) {
                // Graceful fallback: continue with TSR only (OCSP/CRL/cert enrichment may be incomplete)
            }
            sessionWrapper.session.finishSigningLTA(
                tsLtaResponse.base64Tsr,
                validationLTACertificates,
                validationLTACrls,
                validationLTAOCSPs,
            )
        } else {
            error("Failed to begin LTA signing, hash was null.")
        }
    }

    private data class TimestampAndRevocationData(
        val tsResponse: TimestampResponseTO,
        val validationCertificates: List<String>,
        val validationCrls: List<String>,
        val validationOCSPs: List<String>,
    )

    private suspend fun addTimestampAndRevocationInfo(
        sessionWrapper: PodofoSession,
        signedHash: String,
        tsaUrl: String,
        includeRevocationInfo: Boolean,
    ): TimestampAndRevocationData {
        val tsResponse = requestTimestamp(signedHash, tsaUrl)

        val validationCertificates = prepareValidationCertificates(
            sessionWrapper,
            tsResponse.base64Tsr,
        )

        val certificatesForCrlExtraction = listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates
        val crlUrls = mutableSetOf<String>()

        for (certificate in certificatesForCrlExtraction) {
            sessionWrapper.session.getCrlFromCertificate(certificate)?.let { crlUrl ->
                crlUrls.add(crlUrl)
            }
        }

        val validationCrls = if (includeRevocationInfo) fetchCrlDataFromUrls(crlUrls.toList()) else emptyList()
        val validationOCSPs = mutableListOf<String>()

        if (includeRevocationInfo) {
            try {
                val ocspResponse = fetchOcspResponse(
                    sessionWrapper,
                    tsResponse.base64Tsr,
                )
                validationOCSPs.add(ocspResponse)
            } catch (_: Exception) {
                // Graceful fallback: continue without OCSP evidence
            }
        }

        val result = TimestampAndRevocationData(tsResponse, validationCertificates, validationCrls, validationOCSPs)
        return result
    }

    private suspend fun fetchOcspResponse(sessionWrapper: PodofoSession, tsr: String): String {
        var ocspUrl: String
        var base64OcspRequest: String

        try {
            val tsaSignerCert = sessionWrapper.session.extractSignerCertFromTSR(tsr)
            val tsaIssuerCert = sessionWrapper.session.extractIssuerCertFromTSR(tsr)
            ocspUrl = sessionWrapper.session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert)
            base64OcspRequest = sessionWrapper.session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert)
        } catch (e: Exception) {
            try {
                val tsaSignerCert = sessionWrapper.session.extractSignerCertFromTSR(tsr)
                val issuerUrl = sessionWrapper.session.getCertificateIssuerUrlFromCertificate(tsaSignerCert)
                val tsaIssuerCert = fetchCertificateFromUrl(issuerUrl)
                ocspUrl = sessionWrapper.session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert)
                base64OcspRequest = sessionWrapper.session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert)
            } catch (fallbackError: Exception) {
                throw Exception("Failed to fetch OCSP response: Primary error: ${e.message}, Fallback error: ${fallbackError.message}")
            }
        }

        return makeOcspHttpPostRequest(ocspUrl, base64OcspRequest)
    }

    private suspend fun requestTimestamp(hash: String, tsaUrl: String): TimestampResponseTO {
        val tsService = TimestampServiceImpl()
        val tsRequest = TimestampRequestTO(
            signedHash = hash,
            tsaUrl = tsaUrl,
        )
        return tsService.requestTimestamp(tsRequest)
    }

    private suspend fun requestDocTimestamp(hash: String, tsaUrl: String): TimestampResponseTO {
        val tsService = TimestampServiceImpl()
        val tsRequest = TimestampRequestTO(
            signedHash = hash,
            tsaUrl = tsaUrl,
        )
        return tsService.requestDocTimestamp(tsRequest)
    }

    private fun prepareValidationCertificates(sessionWrapper: PodofoSession, timestampResponse: String): List<String> {
        return listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates + timestampResponse
    }

    private suspend fun fetchCrlDataFromUrls(crlUrls: List<String>): List<String> {
        val validationCrlResponses = mutableListOf<String>()
        val revocationService = RevocationServiceImpl()

        for (crlUrl in crlUrls) {
            val crlRequest = CrlRequest(crlUrl = crlUrl)
            val crlInfo = revocationService.getCrlData(request = crlRequest)
            validationCrlResponses.add(crlInfo.crlInfoBase64)
        }
        return validationCrlResponses
    }

    private suspend fun fetchCertificateFromUrl(url: String): String {
        val revocationService = RevocationServiceImpl()
        val request = eu.europa.ec.eudi.rqes.CertificateRequest(certificateUrl = url)
        val response = revocationService.getCertificateData(request)
        return response.certificateBase64
    }

    private suspend fun makeOcspHttpPostRequest(url: String, request: String): String {
        val revocationService = RevocationServiceImpl()
        val ocspRequest = OcspRequest(ocspUrl = url, ocspRequest = request)
        val response = revocationService.getOcspData(ocspRequest)
        return response.ocspInfoBase64
    }

    private fun validateTsaUrlRequirement(docs: List<DocumentToSign>, tsaUrl: String) {
        for (doc in docs) {
            if (doc.conformanceLevel.name != ConformanceLevel.ADES_B_B.toString() && tsaUrl.isEmpty()) {
                error("Missing TSA URL for conformance level: ${doc.conformanceLevel.name}")
            }
        }
    }
}

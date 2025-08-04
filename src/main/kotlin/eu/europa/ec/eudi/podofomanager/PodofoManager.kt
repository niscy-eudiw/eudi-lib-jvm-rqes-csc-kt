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

import android.R.string
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.podofo.android.PoDoFoWrapper
import eu.europa.ec.eudi.rqes.ConformanceLevel
import eu.europa.ec.eudi.rqes.CredentialCertificate
import eu.europa.ec.eudi.rqes.Digest
import eu.europa.ec.eudi.rqes.DocumentDigest
import eu.europa.ec.eudi.rqes.DocumentDigestList
import eu.europa.ec.eudi.rqes.DocumentToSign
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.TimestampRequestTO
import eu.europa.ec.eudi.rqes.TimestampServiceImpl
import eu.europa.ec.eudi.rqes.CrlRequest
import eu.europa.ec.eudi.rqes.RevocationServiceImpl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant


class PodofoManager {
    private var podofoSessions by mutableStateOf<List<PodofoSession>>(emptyList())

    public suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID : HashAlgorithmOID,
        tsaUrl: String
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
                        certificateChain.toTypedArray()
                    )

                    val session = PodofoSession(
                        id = c.toString(),
                        session = podofoWrapper,
                        conformanceLevel = doc.conformanceLevel,
                        endCertificate = endEntityCertificate,
                        chainCertificates = certificateChain
                    )
                    c++

                    podofoWrapper.calculateHash()?.let { hash ->
                        hashes += hash
                        podofoSessions = podofoSessions + session
                    } ?: throw IllegalStateException("Failed to calculate hash for document: ${doc.documentInputPath}")

                } catch (e: Exception) {
                    println("Failed to calculate hash for ${doc.documentOutputPath}")
                }
            }

            if (hashes.size != documents.size) {
                error("Internal error: got ${hashes.size} hashes for ${documents.size} documents")
            }

            val digestEntries = hashes.mapIndexed { idx, rawHash ->
                DocumentDigest(
                    hash  = Digest(rawHash),
                    label = documents[idx].label
                )
            }

            return DocumentDigestList(
                documentDigests     = digestEntries,
                hashAlgorithmOID    = HashAlgorithmOID(hashAlgorithmOID.value),
                hashCalculationTime = Instant.now()
            )
        } catch (e: Exception) {
            println("Error in calculateDocumentHashes for ${documents.map { it.label }}")
            throw e
        }
    }

    public suspend fun createSignedDocuments(signatures: List<String>, tsaUrl: String?) = withContext(Dispatchers.IO) {

        try {
            if (signatures.size != podofoSessions.size) {
                throw IllegalArgumentException("Signatures count (${signatures.size}) does not match session count (${podofoSessions.size})")
            }

            podofoSessions.forEachIndexed { index, sessionWrapper ->
                val signedHash = signatures[index]
                sessionWrapper.session.printState()

                when (sessionWrapper.conformanceLevel) {
                    ConformanceLevel.ADES_B_B -> {
                        handleAdesB_B(sessionWrapper, signedHash)
                    }
                    ConformanceLevel.ADES_B_T -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_T(sessionWrapper, signedHash, tsaUrl)
                    }
                    ConformanceLevel.ADES_B_LT -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LT(sessionWrapper, signedHash, tsaUrl)
                    }
                    ConformanceLevel.ADES_B_LTA -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LTA(sessionWrapper, signedHash, tsaUrl)
                    }
                    else -> throw IllegalArgumentException("Unknown or unsupported conformance level")
                }
            }


        }
        finally {
            podofoSessions = emptyList()
        }
    }

    private fun handleAdesB_B(sessionWrapper: PodofoSession, signedHash: String) {
        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            "",
            mutableListOf(),
            mutableListOf(),
            mutableListOf()
        )
    }

    private suspend fun handleAdesB_T(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        println("Handling ADES-B-T...")
        val tsRequest = TimestampRequestTO(
            signedHash = signedHash,
            tsaUrl = tsaUrl
        )
        val service = TimestampServiceImpl()
        val response = service.requestTimestamp(tsRequest)

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            response.base64Tsr,
            mutableListOf(),
            mutableListOf(),
            mutableListOf()
        )
    }

    private suspend fun handleAdesB_LT(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        val tsRequest = TimestampRequestTO(
            signedHash = signedHash,
            tsaUrl = tsaUrl
        )
        val service = TimestampServiceImpl()
        val tsResponse = service.requestTimestamp(tsRequest)

        val validationCertificates = mutableListOf(sessionWrapper.endCertificate)
        validationCertificates.addAll(sessionWrapper.chainCertificates)
        validationCertificates.add(tsResponse.base64Tsr)

        val certificatesForCrlExtraction = listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates
        val crlUrls = mutableSetOf<String>()

        for (certificate in certificatesForCrlExtraction) {
            try {
                sessionWrapper.session.getCrlFromCertificate(certificate)?.let { crlUrl ->
                    crlUrls.add(crlUrl)
                    println("CRL URL: $crlUrl")
                }
            } catch (e: Exception) {
                println("Could not extract CRL from certificate: ${e.message}")
            }
        }

        val validationCrls = fetchCrlDataFromUrls(crlUrls.toList())

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            tsResponse.base64Tsr,
            validationCertificates,
            validationCrls,
            mutableListOf() // validationOCSPs
        )
    }

    private suspend fun handleAdesB_LTA(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        val tsRequest = TimestampRequestTO(
            signedHash = signedHash,
            tsaUrl = tsaUrl
        )
        val service = TimestampServiceImpl()
        val tsResponse = service.requestTimestamp(tsRequest)

        val validationCertificates = mutableListOf(sessionWrapper.endCertificate)
        validationCertificates.addAll(sessionWrapper.chainCertificates)
        validationCertificates.add(tsResponse.base64Tsr)

        val certificatesForCrlExtraction = listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates
        val crlUrls = mutableSetOf<String>()

        for (certificate in certificatesForCrlExtraction) {
            try {
                sessionWrapper.session.getCrlFromCertificate(certificate)?.let { crlUrl ->
                    crlUrls.add(crlUrl)
                    println("CRL URL: $crlUrl")
                }
            } catch (e: Exception) {
                println("Could not extract CRL from certificate: ${e.message}")
            }
        }

        val validationCrls = fetchCrlDataFromUrls(crlUrls.toList())

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            tsResponse.base64Tsr,
            validationCertificates,
            validationCrls,
            mutableListOf() // validationOCSPs
        )

        // LTA part
        try {
            val ltaRawHash = sessionWrapper.session.beginSigningLTA()
            if (ltaRawHash != null) {
                val tsLtaRequest = TimestampRequestTO(
                    signedHash = ltaRawHash,
                    tsaUrl = tsaUrl
                )
                val tsLtaResponse = service.requestTimestamp(tsLtaRequest)
                sessionWrapper.session.finishSigningLTA(tsLtaResponse.base64Tsr)
            } else {
                println("Failed to begin LTA signing, hash was null.")
            }
        } catch (e: Exception) {
            println("Error during LTA signing process: ${e.message}")
        }
    }

    private suspend fun fetchCrlDataFromUrls(crlUrls: List<String>): List<String> {
        val validationCrlResponses = mutableListOf<String>()
        val revocationService = RevocationServiceImpl()

        for (crlUrl in crlUrls) {
            val crlRequest = CrlRequest(crlUrl = crlUrl)
            try {
                val crlInfo = revocationService.getCrlData(request = crlRequest)
                println("CRL Info Base64: ${crlInfo.crlInfoBase64}")
                validationCrlResponses.add(crlInfo.crlInfoBase64)
            } catch (e: Exception) {
                println("Failed to fetch CRL data for url $crlUrl: ${e.message}")
            }
        }
        return validationCrlResponses
    }

    private fun validateTsaUrlRequirement(docs: List<DocumentToSign>, tsaUrl: String) {
        for (doc in docs) {
            if (doc.conformanceLevel.name != ConformanceLevel.ADES_B_B.toString() && tsaUrl.isEmpty()) {
                error("Missing TSA URL for conformance level: ${doc.conformanceLevel.name}")
            }
        }
    }


}

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
import eu.europa.ec.eudi.rqes.Digest
import eu.europa.ec.eudi.rqes.DocumentDigest
import eu.europa.ec.eudi.rqes.DocumentDigestList
import eu.europa.ec.eudi.rqes.DocumentToSign
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.TimestampRequestTO
import eu.europa.ec.eudi.rqes.TimestampServiceImpl
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

                    val session = PodofoSession(id = c.toString(), session = podofoWrapper)
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

                val tsRequest = TimestampRequestTO(
                    signedHash = signedHash,
                    tsaUrl = tsaUrl ?: ""
                )
                val service = TimestampServiceImpl()
                val response = service.requestTimestamp(tsRequest)

                sessionWrapper.session.finalizeSigningWithSignedHash(signedHash, response.base64Tsr)
            }

        }
        finally {
            podofoSessions = emptyList()
        }
    }

    private fun validateTsaUrlRequirement(docs: List<DocumentToSign>, tsaUrl: String) {
        for (doc in docs) {
            if (doc.conformanceLevel.name != ConformanceLevel.ADES_B_B.toString() && tsaUrl.isEmpty()) {
                error("Missing TSA URL for conformance level: ${doc.conformanceLevel.name}")
            }
        }
    }
}
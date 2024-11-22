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
package eu.europa.ec.eudi.rqes.internal

import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.dss.calculateDigest
import eu.europa.ec.eudi.rqes.internal.http.CalculateHashResponse
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import java.time.Instant

internal class CalculateDocumentHashesImpl() : CalculateDocumentHashes {
    override suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): DocumentDigestList {
        val certificateSource = CommonTrustedCertificateSource() // TODO retrieve this

        val hashesResponse = calculateHash(documents, credentialCertificate, hashAlgorithmOID, certificateSource)

        documents.zip(hashesResponse.hashes).map {
            DocumentDigest(Digest(it.second), it.first.file.label)
        }.let {
            return DocumentDigestList(it, hashAlgorithmOID, hashesResponse.signatureDate)
        }
    }

    private suspend fun calculateHash(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
        certificateSource: CommonTrustedCertificateSource,
    ): CalculateHashResponse {
        val digest = calculateDigest(
            DocumentSignatureParameters(
                documents.first().file.content,
                SignedEnvelopeProperty.ENVELOPED,
                ASiCContainer.NONE,
                HashAlgorithmOID.SHA_256,
                SigningAlgorithmOID.RSA_SHA256,
                credentialCertificate,
                SignatureFormat.P,
                ConformanceLevel.ADES_B_T,
            ),
            certificateSource,
        )

        println(digest)

        return CalculateHashResponse(listOf(), Instant.now())
    }
}

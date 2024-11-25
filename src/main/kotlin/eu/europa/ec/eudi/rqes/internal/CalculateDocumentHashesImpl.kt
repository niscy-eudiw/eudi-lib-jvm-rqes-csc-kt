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
import eu.europa.ec.eudi.rqes.internal.dss.CAdEs
import eu.europa.ec.eudi.rqes.internal.dss.JAdEs
import eu.europa.ec.eudi.rqes.internal.dss.PAdEs
import eu.europa.ec.eudi.rqes.internal.dss.XAdEs
import eu.europa.ec.eudi.rqes.internal.http.CalculateHashResponse
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader
import eu.europa.esig.dss.service.tsp.OnlineTSPSource
import eu.europa.esig.dss.spi.validation.CertificateVerifier
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import java.nio.charset.Charset
import java.time.Instant
import java.util.*

internal class CalculateDocumentHashesImpl(
    private val certificateSource: CommonTrustedCertificateSource,
) : CalculateDocumentHashes {

    override suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): DocumentDigestList {
        val hashesResponse = calculateHash(documents, credentialCertificate, hashAlgorithmOID)

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
    ): CalculateHashResponse {
        val hashes = documents.map {
            val service = when (it.signatureFormat) {
                SignatureFormat.P -> PAdEs(getCertificateVerifier(certificateSource), getTSPSource())
                SignatureFormat.J -> JAdEs(getCertificateVerifier(certificateSource), getTSPSource())
                SignatureFormat.X -> XAdEs()
                SignatureFormat.C -> CAdEs()
            }
            service.calculateDigest(
                DocumentSignatureParameters(
                    it.file.content,
                    it.signedEnvelopeProperty,
                    it.asicContainer,
                    hashAlgorithmOID,
                    it.signAlgo,
                    credentialCertificate,
                    it.signatureFormat,
                    it.conformanceLevel,
                ),
            )
        }.map {
            Base64.getUrlEncoder().encode(it).toString(
                Charset.forName("UTF-8"),
            )
        }

        return CalculateHashResponse(hashes, Instant.now())
    }

    private fun getTSPSource(): TSPSource {
        val tspSource = OnlineTSPSource("https://localhost") // TODO configure tsp source
        tspSource.setDataLoader(TimestampDataLoader())
        return tspSource
    }

    private fun getCertificateVerifier(certificateSource: CommonTrustedCertificateSource): CertificateVerifier {
        val cv: CertificateVerifier = CommonCertificateVerifier()
        cv.setTrustedCertSources(certificateSource)

        // TODO configure cv
        return cv
    }
}

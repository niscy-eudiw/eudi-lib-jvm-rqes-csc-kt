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
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader
import eu.europa.esig.dss.service.tsp.OnlineTSPSource
import eu.europa.esig.dss.spi.validation.CertificateVerifier
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import kotlinx.coroutines.runBlocking
import java.io.InputStream
import java.time.Instant

internal class GetSignedDocumentsImpl(
    private val certificateSource: CommonTrustedCertificateSource,
) : GetSignedDocuments {

    override suspend fun getSignedDocuments(
        documents: List<DocumentToSign>,
        signatures: List<Signature>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
        signatureTimestamp: Instant,
    ): List<InputStream> = runBlocking {
        documents.zip(signatures).map {
            val service = when (it.first.signatureFormat) {
                SignatureFormat.P -> PAdEs(getCertificateVerifier(certificateSource), getTSPSource())
                SignatureFormat.J -> JAdEs(getCertificateVerifier(certificateSource), getTSPSource())
                SignatureFormat.X -> XAdEs()
                SignatureFormat.C -> CAdEs()
            }

            service.signDocument(
                DocumentSignatureParameters(
                    it.first.file.content,
                    it.first.signedEnvelopeProperty,
                    it.first.asicContainer,
                    hashAlgorithmOID,
                    it.first.signAlgo,
                    credentialCertificate,
                    it.first.signatureFormat,
                    it.first.conformanceLevel,
                ),
                it.second,
                hashAlgorithmOID,
                it.first.signAlgo,
            )
        }
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

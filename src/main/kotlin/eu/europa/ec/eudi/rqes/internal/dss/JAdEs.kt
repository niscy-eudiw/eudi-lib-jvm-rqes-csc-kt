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
package eu.europa.ec.eudi.rqes.internal.dss

import eu.europa.ec.eudi.rqes.DocumentSignatureParameters
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.Signature
import eu.europa.ec.eudi.rqes.SigningAlgorithmOID
import eu.europa.esig.dss.enumerations.JWSSerializationType
import eu.europa.esig.dss.enumerations.SigDMechanism
import eu.europa.esig.dss.jades.JAdESSignatureParameters
import eu.europa.esig.dss.jades.JAdESTimestampParameters
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.FileDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.spi.validation.CertificateVerifier
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import java.io.InputStream
import java.util.*

class JAdEs(certificateVerifier: CertificateVerifier, tspSource: TSPSource) : MyCalculateDigest, SignDocument {

    private val signatureService = JAdESService(certificateVerifier)

    init {
        signatureService.setTspSource(tspSource)
    }

    override fun calculateDigest(
        documentSignatureParameters: DocumentSignatureParameters,
    ): ByteArray {
        val dssSignatureParameters = getJAdESSignatureParameters(documentSignatureParameters)

        val dataToSign = signatureService.getDataToSign(
            FileDocument(documentSignatureParameters.document),
            dssSignatureParameters,
        )

        return DSSUtils.digest(
            mapToDSSDigestAlgorithm(documentSignatureParameters.hashAlgorithmOID),
            dataToSign.bytes,
        )
    }

    override fun signDocument(
        documentSignatureParameters: DocumentSignatureParameters,
        signature: Signature,
        hashAlgorithmOID: HashAlgorithmOID,
        signingAlgorithm: SigningAlgorithmOID,
    ): InputStream {
        TODO("Not yet implemented")
    }

    private fun getJAdESSignatureParameters(
        docSignatureParams: DocumentSignatureParameters,
    ) = JAdESSignatureParameters().apply {
        jwsSerializationType = JWSSerializationType.JSON_SERIALIZATION
        sigDMechanism = SigDMechanism.OBJECT_ID_BY_URI_HASH

        signaturePackaging = mapToDSSSignaturePackaging(docSignatureParams.signedEnvelopeProperty)
        signatureLevel = mapToDSSSignatureLevel(docSignatureParams.conformanceLevel, docSignatureParams.signatureFormat)
        digestAlgorithm = mapToDSSDigestAlgorithm(docSignatureParams.hashAlgorithmOID)
        bLevel().signingDate = Date()

        requireNotNull(docSignatureParams.credentialCertificate.certificates) {
            "No certificates provided for signing"
        }

        signingCertificate = CertificateToken(docSignatureParams.credentialCertificate.certificates.first())

        if (docSignatureParams.credentialCertificate.certificates.size > 1) {
            certificateChain =
                docSignatureParams.credentialCertificate.certificates.drop(1).map { CertificateToken(it) }
        }

        val timestampParameters = JAdESTimestampParameters()
        timestampParameters.digestAlgorithm = digestAlgorithm

        contentTimestampParameters = timestampParameters
        signatureTimestampParameters = timestampParameters
        archiveTimestampParameters = timestampParameters
    }
}

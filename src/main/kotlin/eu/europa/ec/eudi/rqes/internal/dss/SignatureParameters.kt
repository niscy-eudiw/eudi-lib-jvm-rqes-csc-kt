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

import eu.europa.ec.eudi.rqes.ASiCContainer
import eu.europa.ec.eudi.rqes.DocumentSignatureParameters
import eu.europa.ec.eudi.rqes.SignatureFormat
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters
import eu.europa.esig.dss.enumerations.JWSSerializationType
import eu.europa.esig.dss.enumerations.SigDMechanism
import eu.europa.esig.dss.jades.JAdESSignatureParameters
import eu.europa.esig.dss.jades.JAdESTimestampParameters
import eu.europa.esig.dss.model.SerializableSignatureParameters
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.pades.PAdESTimestampParameters
import eu.europa.esig.dss.signature.AbstractSignatureParameters
import eu.europa.esig.dss.xades.XAdESSignatureParameters
import eu.europa.esig.dss.xades.XAdESTimestampParameters
import java.util.*

internal fun getSignatureParameters(
    docSignatureParams: DocumentSignatureParameters,
): AbstractSignatureParameters<*> {
    val parameters = if (docSignatureParams.asicContainer != ASiCContainer.NONE) {
        getASicSignatureParameters(docSignatureParams.signatureFormat, docSignatureParams.asicContainer)
    } else {
        when (docSignatureParams.signatureFormat) {
            SignatureFormat.C -> CAdESSignatureParameters()
            SignatureFormat.X -> XAdESSignatureParameters()
            SignatureFormat.P -> PAdESSignatureParameters().apply {
                contentSize *= 2 // double the default signature size TODO check if works
            }

            SignatureFormat.J -> JAdESSignatureParameters().apply {
                jwsSerializationType = JWSSerializationType.JSON_SERIALIZATION
                sigDMechanism = SigDMechanism.OBJECT_ID_BY_URI_HASH
            }
        }
    }

    parameters.apply {
        signaturePackaging = mapToDSSSignaturePackaging(docSignatureParams.signedEnvelopeProperty)
        // signatureLevel = TODO()
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

        val timestampParameters =
            getTimestampParameters(docSignatureParams.signatureFormat, docSignatureParams.asicContainer)
        timestampParameters.digestAlgorithm = digestAlgorithm

        contentTimestampParameters = timestampParameters
        signatureTimestampParameters = timestampParameters
        archiveTimestampParameters = timestampParameters
    }

    return parameters
}

private fun getASicSignatureParameters(
    signatureFormat: SignatureFormat,
    asicContainer: ASiCContainer,
) =
    when (signatureFormat) {
        SignatureFormat.C -> {
            ASiCWithCAdESSignatureParameters().apply {
                aSiC().containerType = mapToDSSASiCContainer(asicContainer)
            }
        }

        SignatureFormat.X -> {
            ASiCWithXAdESSignatureParameters().apply {
                aSiC().containerType = mapToDSSASiCContainer(asicContainer)
            }
        }

        SignatureFormat.P,
        SignatureFormat.J,
            -> error("Unsupported signature format for an ASiC container: $signatureFormat (only CAdES-XAdES are supported)")
    }


private fun getTimestampParameters(
    signatureFormat: SignatureFormat,
    asicContainer: ASiCContainer,
): TimestampParameters =
    if (asicContainer != ASiCContainer.NONE) {
        when (signatureFormat) {
            SignatureFormat.C -> {
                ASiCWithCAdESTimestampParameters().apply {
                    aSiC().containerType = mapToDSSASiCContainer(asicContainer)
                }
            }

            SignatureFormat.X -> XAdESTimestampParameters()
            SignatureFormat.P,
            SignatureFormat.J,
                -> error(
                "Unsupported signature format for an ASiC container: $signatureFormat (only CAdES-XAdES are supported)",
            )
        }
    } else {
        when (signatureFormat) {
            SignatureFormat.C -> CAdESTimestampParameters()
            SignatureFormat.X -> XAdESTimestampParameters()
            SignatureFormat.P -> PAdESTimestampParameters()
            SignatureFormat.J -> JAdESTimestampParameters()
        }
    }

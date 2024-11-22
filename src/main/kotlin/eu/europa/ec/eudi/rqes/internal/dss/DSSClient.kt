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

import eu.europa.ec.eudi.rqes.*
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters
import eu.europa.esig.dss.cades.CAdESSignatureParameters
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters
import eu.europa.esig.dss.enumerations.ASiCContainerType
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.JWSSerializationType
import eu.europa.esig.dss.enumerations.SigDMechanism
import eu.europa.esig.dss.jades.JAdESSignatureParameters
import eu.europa.esig.dss.jades.JAdESTimestampParameters
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.*
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.pades.PAdESSignatureParameters
import eu.europa.esig.dss.pades.PAdESTimestampParameters
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.signature.AbstractSignatureParameters
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.signature.DocumentSignatureService
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.spi.validation.CertificateVerifier
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.spi.x509.tsp.TSPSource
import eu.europa.esig.dss.xades.XAdESSignatureParameters
import eu.europa.esig.dss.xades.XAdESTimestampParameters
import eu.europa.esig.dss.xades.signature.XAdESService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.*

//
// Internal
//

internal suspend fun calculateDigest(
    trustedCertificates: CommonTrustedCertificateSource,
    tspSource: TSPSource? = null,
    parameters: DocumentSignatureParameters
): ByteArray {
    val spec = parameters.signSpec()
    val calculateDigest = calculateDigest(trustedCertificates, tspSource, spec)
    return calculateDigest(parameters.document)
}


//
// Implementation
//

typealias CalculateDigest  = suspend (File)-> ByteArray


private data class SignSpec(
    val asicContainer: ASiCContainer,
    val signedEnvelopeProperty: SignedEnvelopeProperty,
    val hashAlgorithmOID: HashAlgorithmOID,
    val signingAlgorithmOID: SigningAlgorithmOID,
    val credentialCertificate: CredentialCertificate,
    val signatureFormat: SignatureFormat,
    val conformanceLevel: ConformanceLevel,
)

private fun DocumentSignatureParameters.signSpec(): SignSpec {
    return SignSpec(
        asicContainer = asicContainer,
        signedEnvelopeProperty = signedEnvelopeProperty,
        hashAlgorithmOID = hashAlgorithmOID,
        signingAlgorithmOID = signingAlgorithmOID,
        credentialCertificate = credentialCertificate,
        signatureFormat = signatureFormat,
        conformanceLevel = conformanceLevel
    )
}

private fun calculateDigest(
    trustedCertificates: CommonTrustedCertificateSource,
    tspSource: TSPSource? = null,
    spec: SignSpec,
): CalculateDigest {
    val cv = CommonCertificateVerifier().apply { setTrustedCertSources(trustedCertificates) }
    return when (spec.signatureFormat) {
        SignatureFormat.C -> cades(cv, tspSource, spec)
        SignatureFormat.X -> xades(cv, tspSource, spec)
        SignatureFormat.P -> pades(cv, tspSource, spec) {
            contentSize *= 2 // double the default signature size TODO check if works
        }

        SignatureFormat.J -> jades(cv, tspSource, spec) {
            jwsSerializationType = JWSSerializationType.JSON_SERIALIZATION
            sigDMechanism = SigDMechanism.OBJECT_ID_BY_URI_HASH
        }
    }
}


private fun <TP> AbstractSignatureParameters<TP>.setupFor(spec: SignSpec, timestampParameters: TP)
        where TP : TimestampParameters {

    signaturePackaging = mapToDSSSignaturePackaging(spec.signedEnvelopeProperty)
    // signatureLevel = TODO()
    digestAlgorithm = mapToDSSDigestAlgorithm(spec.hashAlgorithmOID)
    bLevel().signingDate = Date()

    requireNotNull(spec.credentialCertificate.certificates) {
        "No certificates provided for signing"
    }

    val (signing, chain) =
        spec.credentialCertificate.certificates.map(::CertificateToken).headAndTail()

    signingCertificate = signing
    certificateChain = chain


    timestampParameters.digestAlgorithm = digestAlgorithm
    contentTimestampParameters = timestampParameters
    signatureTimestampParameters = timestampParameters
    archiveTimestampParameters = timestampParameters
}

//
// Factories
//

private fun cades(
    cv: CertificateVerifier,
    tspSource: TSPSource?,
    spec: SignSpec,
    parametersUse: CAdESSignatureParameters.() -> Unit = {}
): CalculateDigest = CalculateDigestWithDss(
    srv = { CAdESService(cv) },
    tspSource = tspSource,
    algorithm = mapToDSSDigestAlgorithm(spec.hashAlgorithmOID),
    parameters = {
        when (val containerType = spec.asicContainer.toDss()) {
            ASiCContainerType.ASiC_S,
            ASiCContainerType.ASiC_E -> {
                val tp = ASiCWithCAdESTimestampParameters().apply {
                    aSiC().containerType = containerType
                }
                ASiCWithCAdESSignatureParameters().apply {
                    aSiC().containerType = containerType
                    setupFor(spec, tp)
                    parametersUse()
                }
            }

            null -> CAdESSignatureParameters().apply {
                setupFor(spec, CAdESTimestampParameters())
                parametersUse()
            }
        }

    }
)


private fun xades(
    cv: CertificateVerifier,
    tspSource: TSPSource?,
    spec: SignSpec,
    parametersUse: XAdESSignatureParameters.() -> Unit = {}
): CalculateDigest =
    CalculateDigestWithDss(
        srv = { XAdESService(cv) },
        tspSource = tspSource,
        algorithm = mapToDSSDigestAlgorithm(spec.hashAlgorithmOID),
        parameters = {
            when (val containerType = spec.asicContainer.toDss()) {
                null -> XAdESSignatureParameters()
                ASiCContainerType.ASiC_S,
                ASiCContainerType.ASiC_E -> ASiCWithXAdESSignatureParameters().apply {
                    aSiC().containerType = containerType
                }
            }.apply {
                setupFor(spec, XAdESTimestampParameters())
                parametersUse()
            }
        }
    )

private fun pades(
    cv: CertificateVerifier,
    tspSource: TSPSource?,
    spec: SignSpec,
    parametersUse: PAdESSignatureParameters.() -> Unit = {}
): CalculateDigest =
    CalculateDigestWithDss(
        srv = { PAdESService(cv) },
        tspSource = tspSource,
        algorithm = mapToDSSDigestAlgorithm(spec.hashAlgorithmOID),
        parameters = {
            PAdESSignatureParameters().apply {
                setupFor(spec, PAdESTimestampParameters())
                parametersUse()
            }
        }
    )

private fun jades(
    cv: CertificateVerifier,
    tspSource: TSPSource?,
    spec: SignSpec,
    parametersUse: JAdESSignatureParameters.() -> Unit = {}
): CalculateDigest =
    CalculateDigestWithDss(
        srv = { JAdESService(cv) },
        tspSource = tspSource,
        algorithm = mapToDSSDigestAlgorithm(spec.hashAlgorithmOID),
        parameters = {
            JAdESSignatureParameters().apply {
                setupFor(spec, JAdESTimestampParameters())
                parametersUse()
            }
        }
    )


private class CalculateDigestWithDss<SP, TP>(
    srv: () -> DocumentSignatureService<SP, TP>,
    srvCustomization: DocumentSignatureService<SP, TP>.() -> Unit = {},
    val algorithm: DigestAlgorithm,
    private val parameters: () -> SP
) : CalculateDigest
        where SP : SerializableSignatureParameters,
              TP : SerializableTimestampParameters {

    private val srv: DocumentSignatureService<SP, TP> by lazy {
        srv().apply { srvCustomization() }
    }

    private fun toBeSigned(document: File): ToBeSigned {
        val sp = parameters()
        return srv.getDataToSign(FileDocument(document), sp)
    }

    override suspend operator fun invoke(file: File): ByteArray =
        withContext(Dispatchers.IO) {
            val toBeSigned = toBeSigned(file)
            DSSUtils.digest(algorithm, toBeSigned.bytes)
        }


    companion object {
        operator fun <SP : SerializableSignatureParameters, TP : SerializableTimestampParameters> invoke(
            srv: () -> AbstractSignatureService<SP, TP>,
            tspSource: TSPSource?,
            algorithm: DigestAlgorithm,
            parameters: () -> SP,
        ): CalculateDigest = CalculateDigestWithDss(
            srv = srv,
            srvCustomization = { tspSource?.let(::setTspSource) },
            algorithm = algorithm,
            parameters = parameters,
        )
    }
}

//
// Misc
//

private fun <T> List<T>.headAndTail(): Pair<T, List<T>> {
    val head = first()
    val tail = if (size > 1) drop(1) else emptyList()
    return head to tail
}


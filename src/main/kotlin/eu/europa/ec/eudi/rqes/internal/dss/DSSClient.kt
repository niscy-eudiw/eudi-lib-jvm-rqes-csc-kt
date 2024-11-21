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
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService
import eu.europa.esig.dss.cades.signature.CAdESService
import eu.europa.esig.dss.jades.signature.JAdESService
import eu.europa.esig.dss.model.FileDocument
import eu.europa.esig.dss.model.TimestampParameters
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader
import eu.europa.esig.dss.service.tsp.OnlineTSPSource
import eu.europa.esig.dss.signature.AbstractSignatureParameters
import eu.europa.esig.dss.signature.AbstractSignatureService
import eu.europa.esig.dss.signature.DocumentSignatureService
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.spi.validation.CertificateVerifier
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.xades.signature.XAdESService

private fun getSignatureService(
    signatureFormat: SignatureFormat,
    asicContainer: ASiCContainer,
    trustedCertificates: CommonTrustedCertificateSource,
): DocumentSignatureService<*,*> {
    val cv: CertificateVerifier = CommonCertificateVerifier()

    cv.setTrustedCertSources(trustedCertificates)

    // TODO configure cv

    val service: DocumentSignatureService< *,  *> =
        when (signatureFormat) {
            SignatureFormat.C -> CAdESService(cv)
            SignatureFormat.X -> XAdESService(cv)
            SignatureFormat.P -> PAdESService(cv)
            SignatureFormat.J -> JAdESService(cv)
        }

    val tspSource = OnlineTSPSource("https://localhost") // TODO configure tsp source
    tspSource.setDataLoader(TimestampDataLoader())

    service.setTspSource(tspSource)

    return service
}

private fun getASiCSignatureService(
    signatureFormat: SignatureFormat,
    cv: CertificateVerifier,
): AbstractSignatureService< AbstractSignatureParameters< TimestampParameters>,  TimestampParameters> =
    when (signatureFormat) {
        SignatureFormat.C -> ASiCWithCAdESService(cv)
        SignatureFormat.X -> ASiCWithXAdESService(cv)
        SignatureFormat.P,
        SignatureFormat.J,
            -> error("Unsupported signature format for an ASiC container: $signatureFormat (only CAdES-XAdES are supported)")
    }

internal fun calculateDigest(
    documentSignatureParameters: DocumentSignatureParameters,
    trustedCertificates: CommonTrustedCertificateSource,
) {
    val dssSignatureService: DocumentSignatureService< *,*> =
        getSignatureService(
            documentSignatureParameters.signatureFormat,
            documentSignatureParameters.asicContainer,
            trustedCertificates,
        )

    val dssSignatureParameters: AbstractSignatureParameters< *> =
        getSignatureParameters(documentSignatureParameters)

    val dataToSign = dssSignatureService.getDataToSign(
        FileDocument(documentSignatureParameters.document),
        dssSignatureParameters,
    )

    DSSUtils.digest(
        mapToDSSDigestAlgorithm(documentSignatureParameters.hashAlgorithmOID),
        dataToSign.bytes,
    )
}

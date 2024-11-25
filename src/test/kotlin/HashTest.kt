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
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.CalculateDocumentHashesImpl
import eu.europa.ec.eudi.rqes.internal.GetSignedDocumentsImpl
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import java.io.File
import java.time.Instant
import java.util.*

suspend fun main() {
    val pdfDocumentToSign = DocumentToSign(
        Document(
            File(ClassLoader.getSystemResource("sample.pdf").path),
            "A sample pdf",
        ),
        SignatureFormat.P,
        ConformanceLevel.ADES_B_B,
        SigningAlgorithmOID.RSA,
        SignedEnvelopeProperty.ENVELOPED,
        ASiCContainer.NONE,
    )

    val jsonDocumentToSign = DocumentToSign(
        Document(
            File(ClassLoader.getSystemResource("sample.json").path),
            "A sample pdf",
        ),
        SignatureFormat.J,
        ConformanceLevel.ADES_B_B,
        SigningAlgorithmOID.RSA,
        SignedEnvelopeProperty.ENVELOPING,
        ASiCContainer.NONE,
    )

    val hashes = CalculateDocumentHashesImpl(CommonTrustedCertificateSource()).calculateDocumentHashes(
        listOf(pdfDocumentToSign),
        mockCredential.certificate,
        HashAlgorithmOID.SHA_256,
    )

    println(hashes)

    GetSignedDocumentsImpl(CommonTrustedCertificateSource()).getSignedDocuments(
        listOf(pdfDocumentToSign),
        listOf(Signature("asdasd")),
        mockCredential.certificate,
        HashAlgorithmOID.SHA_256,
        Instant.now(),
    ).map {
        File("signed.pdf").writeBytes(it.readAllBytes())
    }
}

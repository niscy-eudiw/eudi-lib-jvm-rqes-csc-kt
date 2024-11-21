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
import java.io.File

suspend fun main() {
    val documentToSign = DocumentToSign(
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

    CalculateDocumentHashesImpl().calculateDocumentHashes(
        listOf(documentToSign),
        mockCredential.certificate,
        HashAlgorithmOID.SHA_256,
    )
}

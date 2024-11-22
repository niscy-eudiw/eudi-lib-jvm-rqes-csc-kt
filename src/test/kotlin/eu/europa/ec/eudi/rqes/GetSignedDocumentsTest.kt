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
package eu.europa.ec.eudi.rqes

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.Test
import kotlin.test.assertNotNull

class GetSignedDocumentsTest {

    @Test
    fun `successful get signed documents`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            calculateHashPostMocker(),
            obtainSignedDocPostMocker(),
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val documentsToSign = listOf(
                DocumentToSign(
                    Document(File(ClassLoader.getSystemResource("sample.pdf").path), "test.pdf"),
                    SignatureFormat.P,
                    ConformanceLevel.ADES_B_B,
                    SigningAlgorithmOID.RSA_SHA256,
                    SignedEnvelopeProperty.ENVELOPED,
                    ASICContainer.NONE,
                ),
            )

            val signedDoc = with(mockServiceAccessAuthorized) {
                val credential =
                    credentialInfo(CredentialsInfoRequest(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"))).getOrThrow()

                val documentDigestList = calculateDocumentHashes(
                    documentsToSign,
                    credential.certificate,
                    HashAlgorithmOID.SHA_256,
                )

                val signatures = listOf(Signature("sdlkjaowseujrvnmxcnvjkshafiea"))

                getSignedDocuments(
                    documentsToSign,
                    signatures,
                    credential.certificate,
                    HashAlgorithmOID.SHA_256,
                    documentDigestList.hashCalculationTime,
                )
            }

            assertNotNull(signedDoc)
        }
    }
}

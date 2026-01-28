/*
 * Copyright (c) 2024-2026 European Commission
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
import java.net.URI
import kotlin.test.Test

class CreateSignedDocumentsTest {

    @Test
    fun `successful create signed documents`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            calculateHashPostMocker(),
            obtainSignedDocPostMocker(),
        )

        with(
            mockPublicClient(
                mockedKtorHttpClientFactory,
                tsaurl = URI("http://ts.cartaodecidadao.pt/tsa/server").toString(),
                includeRevocationInfo = false,
            ),
        ) {
            val documentsToSign = listOf(
                DocumentToSign(
                    documentInputPath = ClassLoader.getSystemResource("sample.pdf").path,
                    documentOutputPath = "signed_test.pdf",
                    label = "test.pdf",
                    signatureFormat = SignatureFormat.P,
                    conformanceLevel = ConformanceLevel.ADES_B_B,
                    signedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPED,
                    asicContainer = ASICContainer.NONE,
                ),
            )

            with(mockServiceAccessAuthorized) {
                val credential =
                    credentialInfo(CredentialsInfoRequest(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"))).getOrThrow()

                val documentDigestList = calculateDocumentHashes(
                    documentsToSign,
                    credential.certificate,
                    HashAlgorithmOID.SHA_256,
                )

                val signatures =
                    listOf(Signature("MEUCIG5WwZcgN68iRdkGNqUYFpn6Q7v5Up1rqU7/9iHYm3MHAiEAmthZYmnIiUAmKsfElOOBcNtEQuI9LKJTeK2Vd9WUBYA="))

                createSignedDocuments(signatures)
            }
        }
    }
}

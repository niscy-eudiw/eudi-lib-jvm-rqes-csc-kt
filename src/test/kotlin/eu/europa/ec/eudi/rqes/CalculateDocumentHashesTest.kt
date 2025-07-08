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
import kotlin.test.*

class CalculateDocumentHashesTest {

    @Test
    fun `successful hash calculation`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            calculateHashPostMocker(),
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val documentDigestList = with(mockServiceAccessAuthorized) {
                val credential = credentialInfo(CredentialsInfoRequest(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"))).getOrThrow()

                calculateDocumentHashes(
                    mockDocumentsToSign,
                    credential.certificate,
                    HashAlgorithmOID.SHA_256,
                )
            }
            assertNotNull(documentDigestList)
            assertEquals(1, documentDigestList.documentDigests.size)
            assertEquals(HashAlgorithmOID.SHA_256, documentDigestList.hashAlgorithmOID)
            assertTrue(documentDigestList.documentDigests[0].hash.value.startsWith("MYIBAzAYBgkqhkiG9w0BCQMxCwYJKoZIhvc"))
        }
    }
}

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
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test

class SignDocImplTest {

    @Test
    fun `successful doc signing with a SCAL1 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            with(mockCredentialAuthorizedSCAL1()) {
                assertThrows<NotImplementedError> {
                    signDoc(
                        mockDocumentsToSign,
                        mockDocumentDigestList,
                        SigningAlgorithmOID.RSA,
                    ).getOrThrow()
                }
            }
        }
    }

    @Test
    fun `successful doc signing with a SCAL2 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            with(mockCredentialAuthorizedSCAL2()) {
                assertThrows<NotImplementedError> {
                    signDoc(
                        mockDocumentsToSign,
                        SigningAlgorithmOID.RSA,
                    ).getOrThrow()
                }
            }
        }
    }
}

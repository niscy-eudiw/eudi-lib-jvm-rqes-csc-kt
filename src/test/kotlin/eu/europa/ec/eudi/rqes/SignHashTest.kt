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

import eu.europa.ec.eudi.rqes.internal.http.SignHashRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SignHashTest {

    @Test
    fun `successful hash signing with a SCAL1 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            signHashPostMocker() { request ->
                runBlocking {
                    assertNotNull(
                        request.headers["Authorization"],
                        "Authorization header is missing in the request",
                    )

                    assertEquals(
                        HttpMethod.Post,
                        request.method,
                        "Request method is not POST",
                    )

                    assertNotNull(
                        request.body,
                        "Request body is missing",
                    )

                    val requestBody = request.body.toByteArray().toString(Charsets.UTF_8)
                    val signHashRequest = Json.decodeFromString<SignHashRequestTO>(requestBody)

                    assertEquals(
                        mockCredential.credentialID.value,
                        signHashRequest.credentialID,
                        "Credential ID is not the expected one",
                    )

                    assertEquals(
                        mockDocumentDigestList.hashAlgorithmOID.value,
                        signHashRequest.hashAlgorithmOID,
                        "Hash algorithm OID not the expected one",
                    )

                    assertEquals(
                        SigningAlgorithmOID.RSA.value,
                        signHashRequest.signAlgorithmOID,
                        "Signing algorithm OID not the expected one",
                    )

                    assertEquals(
                        mockDocumentDigestList.documentDigests[0].hash.asBase64(),
                        signHashRequest.hashes[0],
                        "Hash value is not the expected one",
                    )
                }
            },
        )

        val signatures = with(mockPublicClient(mockedKtorHttpClientFactory)) {
            with(mockCredentialAuthorizedSCAL1()) {
                signHash(mockDocumentDigestList, SigningAlgorithmOID.RSA).getOrThrow()
            }
        }

        assertNotNull(signatures)
    }

    @Test
    fun `successful hash signing with a SCAL2 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            signHashPostMocker() { request ->
                runBlocking {
                    assertNotNull(
                        request.headers["Authorization"],
                        "Authorization header is missing in the request",
                    )

                    assertEquals(
                        HttpMethod.Post,
                        request.method,
                        "Request method is not POST",
                    )

                    assertNotNull(
                        request.body,
                        "Request body is missing",
                    )

                    val requestBody = request.body.toByteArray().toString(Charsets.UTF_8)
                    val signHashRequest = Json.decodeFromString<SignHashRequestTO>(requestBody)

                    assertEquals(
                        mockCredential.credentialID.value,
                        signHashRequest.credentialID,
                        "Credential ID is not the expected one",
                    )

                    assertEquals(
                        mockDocumentDigestList.hashAlgorithmOID.value,
                        signHashRequest.hashAlgorithmOID,
                        "Hash algorithm OID not the expected one",
                    )

                    assertEquals(
                        SigningAlgorithmOID.RSA.value,
                        signHashRequest.signAlgorithmOID,
                        "Signing algorithm OID not the expected one",
                    )

                    assertEquals(
                        mockDocumentDigestList.documentDigests[0].hash.asBase64(),
                        signHashRequest.hashes[0],
                        "Hash value is not the expected one",
                    )
                }
            },
        )

        val signatures = with(mockPublicClient(mockedKtorHttpClientFactory)) {
            with(mockCredentialAuthorizedSCAL2()) {
                signHash(SigningAlgorithmOID.RSA).getOrThrow()
            }
        }

        assertNotNull(signatures)
    }
}

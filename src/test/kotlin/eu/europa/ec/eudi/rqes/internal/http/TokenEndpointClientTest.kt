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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.time.Instant
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals

class TokenEndpointClientTest {

    @Test
    fun `should return token when not using RAR`() = runTest {
        // Given
        val authCode = AuthorizationCode(UUID.randomUUID().toString())
        val credentialAuthorizationSubject = mockCredentialAuthorizationSubject()

        val expectedAccessToken = AccessToken(UUID.randomUUID().toString())
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            RequestMocker(
                requestMatcher = match(URI("http://localhost:8080/token"), HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "access_token": "${expectedAccessToken.accessToken}"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                    )
                },
            ),
        )

        val endpoint = tokenEndpointClient(mockedKtorHttpClientFactory, RarUsage.Never)

        // When
        val result = endpoint.requestAccessTokenAuthFlow(
            authCode,
            mockPKCEVerifier(),
            CredentialAuthorizationRequestType.PassByAuthorizationDetails(credentialAuthorizationSubject),
        )

        // Then
        assert(result.isSuccess)
        assertEquals(expectedAccessToken.accessToken, result.getOrThrow().accessToken.accessToken)
    }

    @Test
    fun `should return token when using RAR`() = runTest {
        // Given
        val authCode = AuthorizationCode(UUID.randomUUID().toString())
        val credentialAuthorizationSubject = mockCredentialAuthorizationSubject()

        val expectedAccessToken = AccessToken(UUID.randomUUID().toString())
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            RequestMocker(
                requestMatcher = match(URI("http://localhost:8080/token"), HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "access_token": "${expectedAccessToken.accessToken}",
                                "token_type": "Bearer",
                                "expires_in": 300,
                                "authorization_details": [{
                                    "type": "credential",
                                    "credentialID": "83c7c559-db74-48da-aacc-d439d415cb81",
                                    "documentDigests": [{
                                        "hash": "${credentialAuthorizationSubject.documentDigestList?.documentDigests[0]?.hash?.asBase64()}",
                                        "label": "${credentialAuthorizationSubject.documentDigestList?.documentDigests[0]?.label}"
                                    }, {
                                        "hash": "${credentialAuthorizationSubject.documentDigestList?.documentDigests[1]?.hash?.asBase64()}",
                                        "label": "${credentialAuthorizationSubject.documentDigestList?.documentDigests[1]?.label}"
                                    }],
                                    "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
                                }]
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                    )
                },
            ),
        )

        val endpoint = tokenEndpointClient(mockedKtorHttpClientFactory, RarUsage.Required)

        // When
        val result = endpoint.requestAccessTokenAuthFlow(
            authCode,
            mockPKCEVerifier(),
            CredentialAuthorizationRequestType.PassByAuthorizationDetails(credentialAuthorizationSubject),
        )

        // Then
        assert(result.isSuccess)
        assertEquals(expectedAccessToken.accessToken, result.getOrThrow().accessToken.accessToken)
    }

    private fun tokenEndpointClient(
        clientFactory: KtorHttpClientFactory,
        rarUsage: RarUsage,
    ) = TokenEndpointClient(
        URI("http://localhost:8080/token").toURL(),
        CSCClientConfig(
            client = OAuth2Client.Public("wallet-client-tester"),
            authFlowRedirectionURI = URI("https://oauthdebugger.com/debug").toURL().toURI(),
            parUsage = ParUsage.IfSupported,
            rarUsage = rarUsage,
        ),
        clientFactory,
    )

    private fun mockPKCEVerifier(): PKCEVerifier {
        return PKCEVerifier(UUID.randomUUID().toString(), UUID.randomUUID().toString())
    }

    private fun mockCredentialAuthorizationSubject(): CredentialAuthorizationSubject {
        val credentialID = CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")
        val hash1 = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
        val hash2 = Digest.Base64Digest("c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0=")
        return credentialAuthorizationSubject(credentialID, listOf(hash1, hash2))
    }

    private fun credentialAuthorizationSubject(credentialID: CredentialID, hashes: List<Digest>) = CredentialAuthorizationSubject(
        CredentialRef.ByCredentialID(credentialID),
        DocumentDigestList(
            hashes.mapIndexed { index, hash ->
                DocumentDigest(
                    hash = hash,
                    label = "sample document ${index + 1}",
                )
            },
            HashAlgorithmOID.SHA_256,
            Instant.now(),
        ),
        1,
    )
}

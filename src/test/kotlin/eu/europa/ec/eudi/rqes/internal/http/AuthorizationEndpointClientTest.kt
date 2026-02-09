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
import java.net.URLEncoder
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertTrue

class AuthorizationEndpointClientTest {

    @Test
    fun `should prepare credential authorization request without PAR, without RAR`() = runTest {
        // Given
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory()

        val credentialID = CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")
        val hash1 = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
        val hash2 = Digest.Base64Digest("c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0=")

        val credentialAuthorizationSubject = credentialAuthorizationSubject(credentialID, listOf(hash1, hash2))
        val endpoint = authEndpointClient(mockedKtorHttpClientFactory, ParUsage.Never, RarUsage.Never)

        // When
        val result = endpoint.submitParOrCreateAuthorizationRequestUrl(
            listOf(Scope.Credential),
            credentialAuthorizationSubject,
            "state",
        ).getOrThrow()

        val authUrl = result.second.value.toString()
        // Assert
        assertTrue(authUrl.startsWith("https://localhost:8084/oauth2/authorize"))
        assertTrue(authUrl.contains(hash1.asBase64URLEncoded()))
        assertTrue(authUrl.contains(URLEncoder.encode(credentialID.value, Charsets.UTF_8)))
    }

    @Test
    fun `should prepare credential authorization request without PAR, with RAR`() = runTest {
        // Given
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory()

        val credentialID = CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")
        val hash1 = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
        val hash2 = Digest.Base64Digest("c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0=")

        val credentialAuthorizationSubject = credentialAuthorizationSubject(credentialID, listOf(hash1, hash2))
        val endpoint = authEndpointClient(mockedKtorHttpClientFactory, ParUsage.Never, RarUsage.Required)

        // When
        val result = endpoint.submitParOrCreateAuthorizationRequestUrl(
            listOf(Scope.Credential),
            credentialAuthorizationSubject,
            "state",
        ).getOrThrow()

        val authUrl = result.second.value.toString()
        // Assert
        assertTrue(authUrl.startsWith("https://localhost:8084/oauth2/authorize"))
        assertTrue(authUrl.contains(URLEncoder.encode(hash2.asBase64(), Charsets.UTF_8)))
        assertTrue(authUrl.contains(URLEncoder.encode(credentialID.value, Charsets.UTF_8)))
    }

    @Test
    fun `should fail when PAR is required but it fails`() = runTest {
        // Given
        val parEndpoint = URI("https://localhost:8084/oauth2/par")
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            RequestMocker(
                requestMatcher = match(parEndpoint, HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "error": "invalid_request",
                                "error_description": "Something went wrong"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.BadRequest,
                        headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                    )
                },
            ),
        )

        val hash1 = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
        val credentialID = CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")
        val credentialAuthorizationSubject = credentialAuthorizationSubject(credentialID, listOf(hash1))
        val endpoint = authEndpointClientWithPar(mockedKtorHttpClientFactory, ParUsage.Required, RarUsage.Never)

        // When
        val result = endpoint.submitParOrCreateAuthorizationRequestUrl(
            listOf(Scope.Credential),
            credentialAuthorizationSubject,
            "state",
        )

        // Assert
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is RQESError.PushedAuthorizationRequestFailed)
    }

    private fun authEndpointClient(
        clientFactory: KtorHttpClientFactory,
        parUsage: ParUsage,
        rarUsage: RarUsage,
    ) = AuthorizationEndpointClient(
        URI("https://localhost:8084/oauth2/authorize").toURL(),
        null,
        CSCClientConfig(
            client = OAuth2Client.Public("wallet-client-tester"),
            authFlowRedirectionURI = URI("https://oauthdebugger.com/debug").toURL().toURI(),
            parUsage = parUsage,
            rarUsage = rarUsage,
        ),
        clientFactory,
    )

    private fun authEndpointClientWithPar(
        clientFactory: KtorHttpClientFactory,
        parUsage: ParUsage,
        rarUsage: RarUsage,
    ) = AuthorizationEndpointClient(
        URI("https://localhost:8084/oauth2/authorize").toURL(),
        URI("https://localhost:8084/oauth2/par").toURL(),
        CSCClientConfig(
            client = OAuth2Client.Public("wallet-client-tester"),
            authFlowRedirectionURI = URI("https://oauthdebugger.com/debug").toURL().toURI(),
            parUsage = parUsage,
            rarUsage = rarUsage,
        ),
        clientFactory,
    )

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

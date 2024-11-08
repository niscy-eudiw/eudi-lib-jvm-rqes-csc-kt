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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.net.URLEncoder
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertTrue

class AuthorizationEndpointClientTest {

    @Test
    fun `should prepare credential authorization request without PAR`() = runTest {
        // Given
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory()

        val credentialID = CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")
        val hash1 = "MYIBAzAYBgkqhkiG9w0BC="
        val hash2 = "MYIBAzAYBgkqhkiG9w0BC="

        val endpoint = AuthorizationEndpointClient(
            URI("https://localhost:8084/oauth2/authorize").toURL(),
            null,
            CSCClientConfig(
                client = OAuth2Client.Public("wallet-client-tester"),
                authFlowRedirectionURI = URI("https://oauthdebugger.com/debug").toURL().toURI(),
                scaBaseURL = URI("http://localhost:8080").toURL(),
                parUsage = ParUsage.IfSupported,
            ),
            mockedKtorHttpClientFactory,
        )

        // When
        val result = endpoint.submitParOrCreateAuthorizationRequestUrl(
            listOf(Scope.Credential),
            CredentialAuthorizationSubject(
                CredentialRef.ByCredentialID(credentialID),
                DocumentDigestList(
                    listOf(
                        DocumentDigest(
                            Digest(hash1),
                            "sample document 1",
                        ),
                        DocumentDigest(
                            Digest(hash2),
                            "sample document 2",
                        ),
                    ),
                    HashAlgorithmOID.SHA_256,
                    Instant.now(),
                ),
                1,
            ),
            "state",
        ).getOrThrow()

        // Assert
        assertTrue(result.second.value.toString().startsWith("https://localhost:8084/oauth2/authorize"))
        assertTrue(result.second.value.toString().contains(URLEncoder.encode(hash1, Charsets.UTF_8)))
        assertTrue(result.second.value.toString().contains(URLEncoder.encode(credentialID.value, Charsets.UTF_8)))
    }
}

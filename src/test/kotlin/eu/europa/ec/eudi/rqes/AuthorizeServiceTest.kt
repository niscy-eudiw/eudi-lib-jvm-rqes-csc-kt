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

import eu.europa.ec.eudi.rqes.internal.http.PushedAuthorizationRequestResponseTO
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointForm
import io.ktor.client.engine.mock.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.*

class AuthorizeServiceTest {

    @Test
    fun `successful service authorization with authorization code flow`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.CODE_VERIFIER_PARAM],
                    "PKCE code verifier was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_CODE_PARAM],
                    "Parameter ${TokenEndpointForm.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.REDIRECT_URI_PARAM],
                    "Parameter ${TokenEndpointForm.REDIRECT_URI_PARAM} was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.CLIENT_ID_PARAM],
                    "Parameter ${TokenEndpointForm.CLIENT_ID_PARAM} was expected but not sent.",
                )
                val grantType = form.formData[TokenEndpointForm.GRANT_TYPE_PARAM]
                assertNotNull(
                    grantType,
                    "Parameter ${TokenEndpointForm.GRANT_TYPE_PARAM} was expected but not sent.",
                )
                assertEquals(
                    TokenEndpointForm.AUTHORIZATION_CODE_GRANT,
                    grantType,
                    "Expected grant_type is ${TokenEndpointForm.AUTHORIZATION_CODE_GRANT} but instead sent $grantType.",
                )
            },
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val authRequestPrepared = prepareServiceAuthorizationRequest().getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.value.state
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()
        }
    }

    @Test
    fun `successful service authorization with pushed authorization code flow`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            parPostMocker("/pushed_authorize") { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )
                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertTrue("Missing scope 'service'") {
                    form.formData["scope"]?.contains("service") ?: false
                }
                assertNotNull(
                    form.formData["code_challenge"],
                    "PKCE code challenge was expected but not sent.",
                )
                assertNotNull(
                    form.formData["code_challenge_method"],
                    "PKCE code challenge method was expected but not sent.",
                )
            },
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.CODE_VERIFIER_PARAM],
                    "PKCE code verifier was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_CODE_PARAM],
                    "Parameter ${TokenEndpointForm.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.REDIRECT_URI_PARAM],
                    "Parameter ${TokenEndpointForm.REDIRECT_URI_PARAM} was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.CLIENT_ID_PARAM],
                    "Parameter ${TokenEndpointForm.CLIENT_ID_PARAM} was expected but not sent.",
                )
                val grantType = form.formData[TokenEndpointForm.GRANT_TYPE_PARAM]
                assertNotNull(
                    grantType,
                    "Parameter ${TokenEndpointForm.GRANT_TYPE_PARAM} was expected but not sent.",
                )
                assertEquals(
                    TokenEndpointForm.AUTHORIZATION_CODE_GRANT,
                    grantType,
                    "Expected grant_type is ${TokenEndpointForm.AUTHORIZATION_CODE_GRANT} but instead sent $grantType.",
                )
            },
        )

        with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val authRequestPrepared = prepareServiceAuthorizationRequest().getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.value.state
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()
        }
    }

    @Test
    fun `successful service authorization with client credentials flow`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.CLIENT_ID_PARAM],
                    "Parameter ${TokenEndpointForm.CLIENT_ID_PARAM} was expected but not sent.",
                )
                assertNotNull(
                    form.formData[TokenEndpointForm.CLIENT_SECRET_PARAM],
                    "Parameter ${TokenEndpointForm.CLIENT_SECRET_PARAM} was expected but not sent.",
                )
                val grantType = form.formData[TokenEndpointForm.GRANT_TYPE_PARAM]
                assertNotNull(
                    grantType,
                    "Parameter ${TokenEndpointForm.GRANT_TYPE_PARAM} was expected but not sent.",
                )
                assertEquals(
                    TokenEndpointForm.CLIENT_CREDENTIALS_GRANT,
                    grantType,
                    "Expected grant_type is ${TokenEndpointForm.CLIENT_CREDENTIALS_GRANT} but instead sent $grantType.",
                )
            },
        )

        with(mockConfidentialClient(mockedKtorHttpClientFactory)) {
            authorizeWithClientCredentials().getOrThrow()
        }
    }

    @Test
    fun `when par endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            RequestMocker(
                requestMatcher = endsWith("/pushed_authorize", HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = Json.encodeToString(
                            PushedAuthorizationRequestResponseTO.Failure(
                                "invalid_request",
                                "The redirect_uri is not valid for the given client",
                            ),
                        ),
                        status = HttpStatusCode.BadRequest,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
            ),
        )

        val cscClient = CSCClient.oauth2(
            rsspMetadata = rsspMetadata(),
            cscClientConfig = CSCClientConfig(
                client = OAuth2Client.Public("client-id"),
                authFlowRedirectionURI = URI("https://example.com/redirect"),
                parUsage = ParUsage.Required,
            ),
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        ).getOrThrow()
        with(cscClient) {
            prepareServiceAuthorizationRequest().fold(
                onSuccess = {
                    fail("Exception expected to be thrown")
                },
                onFailure = {
                    assertTrue("Expected PushedAuthorizationRequestFailed to be thrown but was not") {
                        it is RQESError.PushedAuthorizationRequestFailed
                    }
                },
            )
        }
    }
}

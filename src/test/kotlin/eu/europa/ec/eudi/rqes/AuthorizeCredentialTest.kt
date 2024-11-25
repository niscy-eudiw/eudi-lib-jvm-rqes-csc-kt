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

import eu.europa.ec.eudi.rqes.internal.http.AuthorizationDetailTO
import eu.europa.ec.eudi.rqes.internal.http.DocumentDigestTO
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointForm
import io.ktor.client.request.forms.*
import kotlinx.coroutines.test.runTest
import java.util.*
import kotlin.test.*

class AuthorizeCredentialTest {

    @Test
    fun `successful SCAL1 credential authorization with authorization code flow without RAR`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker("eu/europa/ec/eudi/rqes/internal/credentials_info_scal1_oauth_valid.json"),
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was not expected but sent.",
                )
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

        with(mockPublicClient(mockedKtorHttpClientFactory, rarUsage = RarUsage.Never)) {
            val authRequestPrepared =
                prepareCredentialAuthorizationRequest(scal1CredentialAuthorizationSubject).getOrThrow()

            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.authorizationRequestPrepared.state

            val credentialAuthorized = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()

            assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialAuthorized.credentialID.value)
        }
    }

    @Test
    fun `successful SCAL2 credential authorization with authorization code flow without RAR`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was not expected but sent.",
                )
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

        with(mockPublicClient(mockedKtorHttpClientFactory, rarUsage = RarUsage.Never)) {
            val authRequestPrepared =
                prepareCredentialAuthorizationRequest(scal2CredentialAuthorizationSubject).getOrThrow()

            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.authorizationRequestPrepared.state

            val credentialAuthorized = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()

            assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialAuthorized.credentialID.value)
        }
    }

    @Test
    fun `successful SCAL2 credential authorization with authorization code flow with RAR`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            tokenPostMocker(
                listOf(
                    AuthorizationDetailTO(
                        type = "credential",
                        credentialID = "83c7c559-db74-48da-aacc-d439d415cb81",
                        numSignatures = "1",
                        documentDigests = listOf(
                            DocumentDigestTO(
                                hash = "digest",
                                label = "test document",
                            ),
                        ),
                        hashAlgorithmOID = "2.16.840.1.101.3.4.2.8",
                    ),
                ),
            ) { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was expected but not sent.",
                )
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

        with(mockPublicClient(mockedKtorHttpClientFactory, rarUsage = RarUsage.Required)) {
            val authRequestPrepared =
                prepareCredentialAuthorizationRequest(scal2CredentialAuthorizationSubject).getOrThrow()

            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.authorizationRequestPrepared.state

            val credentialAuthorized = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()

            assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialAuthorized.credentialID.value)
        }
    }

    @Test
    fun `successful SCAL2 credential authorization with authorization code flow with PAR without RAR`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            parPostMocker("/pushed_authorize") { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was not expected but sent.",
                )
            },
            tokenPostMocker { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was not expected but sent.",
                )
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

        with(mockPublicClient(mockedKtorHttpClientFactory, parUsage = ParUsage.Required, rarUsage = RarUsage.Never)) {
            val authRequestPrepared =
                prepareCredentialAuthorizationRequest(scal2CredentialAuthorizationSubject).getOrThrow()

            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.authorizationRequestPrepared.state

            val credentialAuthorized = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()

            assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialAuthorized.credentialID.value)
        }
    }

    @Test
    fun `successful SCAL2 credential authorization with authorization code flow with PAR with RAR`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            parPostMocker("/pushed_authorize") { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was expected but not sent.",
                )
            },
            tokenPostMocker(
                listOf(
                    AuthorizationDetailTO(
                        type = "credential",
                        credentialID = "83c7c559-db74-48da-aacc-d439d415cb81",
                        numSignatures = "1",
                        documentDigests = listOf(
                            DocumentDigestTO(
                                hash = "digest",
                                label = "test document",
                            ),
                        ),
                        hashAlgorithmOID = "2.16.840.1.101.3.4.2.8",
                    ),
                ),
            ) { request ->
                assertEquals(
                    "application/x-www-form-urlencoded; charset=UTF-8",
                    request.body.contentType?.toString(),
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                )

                val form = assertIs<FormDataContent>(request.body, "Not a form post")

                assertNotNull(
                    form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS],
                    "authorization_details was expected but not sent.",
                )
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

        with(
            mockPublicClient(
                mockedKtorHttpClientFactory,
                parUsage = ParUsage.Required,
                rarUsage = RarUsage.Required,
            ),
        ) {
            val authRequestPrepared =
                prepareCredentialAuthorizationRequest(scal2CredentialAuthorizationSubject).getOrThrow()

            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.authorizationRequestPrepared.state

            val credentialAuthorized = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()

            assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialAuthorized.credentialID.value)
        }
    }

    private val scal1CredentialAuthorizationSubject = CredentialAuthorizationSubject(
        CredentialRef.ByCredentialID(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")),
        documentDigestList = null,
        numSignatures = 1,
    )

    private val scal2CredentialAuthorizationSubject = CredentialAuthorizationSubject(
        CredentialRef.ByCredentialID(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81")),
        mockDocumentDigestList,
        numSignatures = 1,
    )
}

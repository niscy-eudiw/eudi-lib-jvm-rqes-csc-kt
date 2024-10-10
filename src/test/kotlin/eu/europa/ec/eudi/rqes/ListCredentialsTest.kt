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

import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointForm
import io.ktor.client.request.forms.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class ListCredentialsTest {

    @Test
    fun `successful retrieval of credentials list`() = runTest {
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
            credentialsListPostMocker(),
        )

        val cscClient = CSCClient.oauth2(
            rsspMetadata = rsspMetadata(),
            cscClientConfig = CSCClientConfig(
                client = OAuth2Client.Public("client-id"),
                authFlowRedirectionURI = URI("https://example.com/redirect"),
                parUsage = ParUsage.Never,
            ),
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        ).getOrThrow()

        with(cscClient) {
            val authRequestPrepared = prepareServiceAuthorizationRequest().getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.value.state
            val authorizedService = authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                .getOrThrow()
            with(authorizedService) {
                val credentialsList = listCredentials(CredentialsListRequest()).getOrThrow()
                println(credentialsList)
            }
        }
    }
}

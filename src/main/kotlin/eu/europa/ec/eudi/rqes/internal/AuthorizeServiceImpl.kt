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
package eu.europa.ec.eudi.rqes.internal

import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.AuthorizationError.InvalidAuthorizationState
import eu.europa.ec.eudi.rqes.internal.http.AuthorizationEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointClient
import java.time.Instant
import com.nimbusds.oauth2.sdk.id.State as NimbusState

internal data class TokenResponse(
    val accessToken: AccessToken,
    val refreshToken: RefreshToken?,
    val timestamp: Instant,
    val credentialID: CredentialID?,
    val credentialAuthorizationSubject: CredentialAuthorizationSubject?,
)

internal class AuthorizeServiceImpl(
    private val authorizationEndpointClient: AuthorizationEndpointClient?,
    private val tokenEndpointClient: TokenEndpointClient,
) : AuthorizeService {

    override suspend fun prepareServiceAuthorizationRequest(walletState: String?): Result<ServiceAuthorizationRequestPrepared> =
        runCatching {
            checkNotNull(authorizationEndpointClient)
            val scopes = listOf(Scope(Scope.Service.value))
            val state = walletState ?: NimbusState().value
            val (codeVerifier, authorizationCodeUrl) = authorizationEndpointClient.submitParOrCreateAuthorizationRequestUrl(
                scopes = scopes,
                state = state,
            ).getOrThrow()
            ServiceAuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state)
        }

    override suspend fun ServiceAuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
    ): Result<ServiceAccessAuthorized> =
        runCatching {
            ensure(serverState == value.state) { InvalidAuthorizationState() }
            val tokenResponse = tokenEndpointClient.requestAccessTokenAuthFlow(
                authorizationCode,
                value.pkceVerifier,
                credentialAuthorizationRequestType = null,
            )
            val (accessToken, refreshToken, timestamp) = tokenResponse.getOrThrow()

            ServiceAccessAuthorized(OAuth2Tokens(accessToken, refreshToken, timestamp))
        }

    override suspend fun authorizeWithClientCredentials(): Result<ServiceAccessAuthorized> = runCatching {
        val tokenResponse = tokenEndpointClient.requestAccessTokenClientCredentialsFlow(Scope.Service)
        val (accessToken, refreshToken, timestamp) = tokenResponse.getOrThrow()
        ServiceAccessAuthorized(OAuth2Tokens(accessToken, refreshToken, timestamp))
    }
}

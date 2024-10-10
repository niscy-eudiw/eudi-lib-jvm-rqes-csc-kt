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
import eu.europa.ec.eudi.rqes.internal.TokenResponse
import io.ktor.client.call.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.time.Clock
import java.time.Duration

/**
 * Sealed hierarchy of possible responses to an Access Token request.
 */
internal sealed interface TokenResponseTO {

    /**
     * Successful request submission.
     *
     * @param accessToken The access token.
     * @param refreshToken The refresh token.
     * @param expiresIn Token time to live.
     */
    @Serializable
    data class Success(
        @SerialName("token_type") val tokenType: String? = "Bearer",
        @SerialName("access_token") val accessToken: String,
        @SerialName("expires_in") val expiresIn: Long? = null,
        @SerialName("refresh_token") val refreshToken: String? = null,
        @SerialName("credentialID") val credentialID: String? = null,
    ) : TokenResponseTO

    /**
     * Request failed
     *
     * @param error The error reported from the authorization server.
     * @param errorDescription A description of the error.
     */
    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : TokenResponseTO

    fun tokensOrFail(clock: Clock): TokenResponse =
        when (this) {
            is Success -> {
                TokenResponse(
                    accessToken = AccessToken(
                        accessToken,
                        expiresIn?.let { Duration.ofSeconds(it) },
                    ),
                    refreshToken = refreshToken?.let { RefreshToken(it, 0) },
                    timestamp = clock.instant(),
                )
            }

            is Failure -> throw RQESError.AccessTokenRequestFailed(error, errorDescription)
        }
}

internal class TokenEndpointClient(
    private val clock: Clock,
    private val client: OAuth2Client,
    private val authFlowRedirectionURI: URI,
    private val tokenEndpoint: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    constructor(
        tokenEndpoint: URL,
        config: CSCClientConfig,
        ktorHttpClientFactory: KtorHttpClientFactory,
    ) : this(
        config.clock,
        config.client,
        config.authFlowRedirectionURI,
        tokenEndpoint,
        ktorHttpClientFactory,
    )

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * authorization code flow
     *
     * @param authorizationCode The authorization code generated from authorization server.
     * @param pkceVerifier  The code verifier that was used when submitting the Pushed Authorization Request.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: AuthorizationCode,
        pkceVerifier: PKCEVerifier,
    ): Result<TokenResponse> = runCatching {
        val params = TokenEndpointForm.authCodeFlow(
            authorizationCode = authorizationCode,
            redirectionURI = authFlowRedirectionURI,
            clientId = client.clientId,
            pkceVerifier = pkceVerifier,
        )
        requestAccessToken(params).tokensOrFail(clock)
    }

    /**
     * Submits a request for refreshing an access token in authorization server's token endpoint passing
     * the refresh token
     * @param refreshToken the token to be used for refreshing the access token
     *
     * @return the token end point response, which will include a new [TokenResponse.accessToken] and possibly
     * a new [TokenResponse.refreshToken]
     */
    suspend fun refreshAccessToken(refreshToken: RefreshToken): Result<TokenResponse> = runCatching {
        val params = TokenEndpointForm.refreshAccessToken(client.clientId, refreshToken)
        requestAccessToken(params).tokensOrFail(clock = clock)
    }

    private suspend fun requestAccessToken(
        params: Map<String, String>,
    ): TokenResponseTO =
        ktorHttpClientFactory().use { client ->
            val formParameters = Parameters.build {
                params.entries.forEach { (k, v) -> append(k, v) }
            }
            val response = client.submitForm(tokenEndpoint.toString(), formParameters)
            if (response.status.isSuccess()) response.body<TokenResponseTO.Success>()
            else response.body<TokenResponseTO.Failure>()
        }

    suspend fun requestAccessTokenClientCredentialsFlow(scope: Scope?): Result<TokenResponse> = runCatching {
        require(client is OAuth2Client.Confidential.PasswordProtected) { "Client must be confidential" }
        val params = TokenEndpointForm.clientCredentialsFlow(client.clientId, client.clientSecret, scope)
        requestAccessToken(params).tokensOrFail(clock)
    }
}

internal object TokenEndpointForm {
    const val AUTHORIZATION_CODE_GRANT = "authorization_code"
    const val CLIENT_CREDENTIALS_GRANT = "client_credentials"
    const val REFRESH_TOKEN = "refresh_token"
    const val REDIRECT_URI_PARAM = "redirect_uri"
    const val CODE_VERIFIER_PARAM = "code_verifier"
    const val AUTHORIZATION_CODE_PARAM = "code"
    const val CLIENT_ID_PARAM = "client_id"
    const val CLIENT_SECRET_PARAM = "client_secret"
    const val GRANT_TYPE_PARAM = "grant_type"
    const val REFRESH_TOKEN_PARAM = "refresh_token"
    const val CLIENT_DATA = "clientData"
    const val SCOPE = "scope"

    fun authCodeFlow(
        clientId: String,
        authorizationCode: AuthorizationCode,
        redirectionURI: URI,
        pkceVerifier: PKCEVerifier,
        clientData: String? = null,
    ): Map<String, String> = buildMap {
        put(CLIENT_ID_PARAM, clientId)
        put(GRANT_TYPE_PARAM, AUTHORIZATION_CODE_GRANT)
        put(AUTHORIZATION_CODE_PARAM, authorizationCode.code)
        put(REDIRECT_URI_PARAM, redirectionURI.toString())
        put(CODE_VERIFIER_PARAM, pkceVerifier.codeVerifier)
        clientData?.let { put(CLIENT_DATA, clientData) }
    }.toMap()

    fun clientCredentialsFlow(
        clientId: String,
        clientSecret: String,
        scope: Scope?,
    ): Map<String, String> = buildMap {
        put(GRANT_TYPE_PARAM, CLIENT_CREDENTIALS_GRANT)
        put(CLIENT_ID_PARAM, clientId)
        put(CLIENT_SECRET_PARAM, clientSecret)
        scope?.let { put(SCOPE, it.value) }
    }

    fun refreshAccessToken(
        clientId: String,
        refreshToken: RefreshToken,
    ): Map<String, String> = buildMap {
        put(CLIENT_ID_PARAM, clientId)
        put(GRANT_TYPE_PARAM, REFRESH_TOKEN)
        put(REFRESH_TOKEN_PARAM, refreshToken.refreshToken)
    }
}

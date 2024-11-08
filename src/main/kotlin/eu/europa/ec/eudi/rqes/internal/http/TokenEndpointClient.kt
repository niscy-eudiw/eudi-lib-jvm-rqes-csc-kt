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

import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.TokenResponse
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointForm.CLIENT_ID_PARAM
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointForm.CLIENT_SECRET_PARAM
import eu.europa.ec.eudi.rqes.internal.toNimbusAuthDetail
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.time.Clock
import java.time.Duration
import java.time.Instant

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
        @SerialName("authorization_details") val authorizationDetails: List<AuthorizationDetailTO>? = null,
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
                    credentialID = credentialID?.let { CredentialID(it) },
                    credentialAuthorizationSubject = authorizationDetails?.let {
                        CredentialAuthorizationSubject(
                            CredentialRef.ByCredentialID(CredentialID(authorizationDetails.first().credentialID)),
                            DocumentDigestList(
                                documentDigests = authorizationDetails.first().documentDigests.map {
                                    DocumentDigest(
                                        hash = Digest(it.hash),
                                        label = it.label,
                                    )
                                },
                                hashAlgorithmOID = HashAlgorithmOID(authorizationDetails.first().hashAlgorithmOID),
                                hashCalculationTime = Instant.now(),
                            ),
                            authorizationDetails.first().numSignatures?.toInt(),
                        )
                    },
                )
            }

            is Failure -> throw RQESError.AccessTokenRequestFailed(error, errorDescription)
        }
}

@Serializable
internal data class AuthorizationDetailTO(
    @SerialName("type") val type: String,
    @SerialName("credentialID") val credentialID: String,
    @SerialName("numSignatures") val numSignatures: String? = "1",
    @SerialName("documentDigests") val documentDigests: List<DocumentDigestTO>,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String,
)

@Serializable
internal data class DocumentDigestTO(
    @SerialName("hash") val hash: String,
    @SerialName("label") val label: String?,
)

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
     * @param credentialAuthorizationRequestType The credential authorization details that was used during the authorization step.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: AuthorizationCode,
        pkceVerifier: PKCEVerifier,
        credentialAuthorizationRequestType: CredentialAuthorizationRequestType?,
    ): Result<TokenResponse> = runCatching {
        val authDetails = credentialAuthorizationRequestType?.let {
            when (it) {
                is CredentialAuthorizationRequestType.PassByAuthorizationDetails -> {
                    credentialAuthorizationRequestType.credentialAuthorizationSubject.toNimbusAuthDetail()
                }
                is CredentialAuthorizationRequestType.PassByScope -> null
            }
        }

        val params = TokenEndpointForm.authCodeFlow(
            authorizationCode = authorizationCode,
            redirectionURI = authFlowRedirectionURI,
            client = client,
            pkceVerifier = pkceVerifier,
            authorizationDetails = authDetails,
        )
        requestAccessToken(params, client).tokensOrFail(clock)
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
        val params = TokenEndpointForm.refreshAccessToken(client, refreshToken)
        requestAccessToken(params, client).tokensOrFail(clock = clock)
    }

    private suspend fun requestAccessToken(
        params: Map<String, String>,
        oauth2Client: OAuth2Client,
    ): TokenResponseTO =
        ktorHttpClientFactory().use { client ->
            val formParameters = Parameters.build {
                params.entries.forEach { (k, v) -> append(k, v) }
            }

            val response = client.submitForm(tokenEndpoint.toString(), formParameters) {
                when (oauth2Client) {
                    is OAuth2Client.Confidential.ClientSecretBasic ->
                        headers {
                            basicAuth(username = oauth2Client.clientId, password = oauth2Client.clientSecret)
                        }

                    is OAuth2Client.Public -> {}
                    is OAuth2Client.Confidential.ClientSecretPost -> {}
                }
            }
            if (response.status.isSuccess()) response.body<TokenResponseTO.Success>()
            else response.body<TokenResponseTO.Failure>()
        }

    suspend fun requestAccessTokenClientCredentialsFlow(scope: Scope?): Result<TokenResponse> = runCatching {
        require(client is OAuth2Client.Confidential) { "Client must be confidential" }
        val params = TokenEndpointForm.clientCredentialsFlow(client, scope)
        requestAccessToken(params, client).tokensOrFail(clock)
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
    const val AUTHORIZATION_DETAILS = "authorization_details"

    fun authCodeFlow(
        client: OAuth2Client,
        authorizationCode: AuthorizationCode,
        redirectionURI: URI,
        pkceVerifier: PKCEVerifier,
        clientData: String? = null,
        authorizationDetails: AuthorizationDetail?,
    ): Map<String, String> = buildMap {
        put(GRANT_TYPE_PARAM, AUTHORIZATION_CODE_GRANT)
        put(AUTHORIZATION_CODE_PARAM, authorizationCode.code)
        put(REDIRECT_URI_PARAM, redirectionURI.toString())
        put(CODE_VERIFIER_PARAM, pkceVerifier.codeVerifier)
        clientData?.let { put(CLIENT_DATA, clientData) }
        authorizationDetails?.let {
            put(
                AUTHORIZATION_DETAILS,
                "[${authorizationDetails.toJSONObject().toJSONString()}]",
            )
        }
        putAll(clientAuthenticationParams(client))
    }

    fun clientCredentialsFlow(
        client: OAuth2Client,
        scope: Scope?,
    ): Map<String, String> = buildMap {
        put(GRANT_TYPE_PARAM, CLIENT_CREDENTIALS_GRANT)
        scope?.let { put(SCOPE, it.value) }
        putAll(clientAuthenticationParams(client))
    }

    fun refreshAccessToken(
        client: OAuth2Client,
        refreshToken: RefreshToken,
    ): Map<String, String> = buildMap {
        putAll(clientAuthenticationParams(client))
        put(GRANT_TYPE_PARAM, REFRESH_TOKEN)
        put(REFRESH_TOKEN_PARAM, refreshToken.refreshToken)
    }
}

private fun clientAuthenticationParams(client: OAuth2Client): Map<String, String> =
    buildMap {
        when (client) {
            is OAuth2Client.Public -> {
                put(CLIENT_ID_PARAM, client.clientId)
            }

            is OAuth2Client.Confidential.ClientSecretPost -> {
                put(CLIENT_ID_PARAM, client.clientId)
                put(CLIENT_SECRET_PARAM, client.clientSecret)
            }

            is OAuth2Client.Confidential.ClientSecretBasic -> {
                put(CLIENT_ID_PARAM, client.clientId)
            }
        }
    }

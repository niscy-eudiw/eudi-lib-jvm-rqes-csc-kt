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

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import com.nimbusds.openid.connect.sdk.Prompt
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.Scope
import eu.europa.ec.eudi.rqes.internal.toNimbusAuthDetail
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import com.nimbusds.oauth2.sdk.Scope as NimbusScope

internal sealed interface PushedAuthorizationRequestResponseTO {

    /**
     * Successful request submission.
     *
     * @param requestURI A unique identifier of the authorization request.
     * @param expiresIn Time to live of the authorization request.
     */
    @Serializable
    data class Success(
        @SerialName("request_uri") val requestURI: String,
        @SerialName("expires_in") val expiresIn: Long = 5,
    ) : PushedAuthorizationRequestResponseTO

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
    ) : PushedAuthorizationRequestResponseTO
}

internal class AuthorizationEndpointClient(
    private val authorizationEndpoint: URL,
    private val pushedAuthorizationRequestEndpoint: URL?,
    private val cscClientConfig: CSCClientConfig,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    private val supportsPar: Boolean
        get() = pushedAuthorizationRequestEndpoint != null

    // TODO determine if the auth server supports RAR (not possible if the server doesn't advertise it)
    private val supportsRar: Boolean
        get() = true

    suspend fun submitParOrCreateAuthorizationRequestUrl(
        scopes: List<Scope>,
        authorizationSubject: CredentialAuthorizationSubject? = null,
        state: String,
    ): Result<Triple<PKCEVerifier, HttpsUrl, CredentialAuthorizationRequestType?>> {
        val usePar = when (cscClientConfig.parUsage) {
            ParUsage.IfSupported -> supportsPar
            ParUsage.Never -> false
            ParUsage.Required -> {
                require(supportsPar) {
                    "PAR usage is required, yet authorization server doesn't advertise PAR endpoint"
                }
                true
            }
        }

        val useRichAuthorizationRequests = when (cscClientConfig.rarUsage) {
            RarUsage.IfSupported -> supportsRar
            RarUsage.Never -> false
            RarUsage.Required -> {
                require(supportsRar) {
                    "Rich Authorization Requests usage is required, yet authorization server doesn't support it"
                }
                true
            }
        }

        val credentialAuthorizationRequestType = authorizationSubject?.let {
            when (useRichAuthorizationRequests) {
                true -> CredentialAuthorizationRequestType.PassByAuthorizationDetails(authorizationSubject)
                false -> CredentialAuthorizationRequestType.PassByScope(authorizationSubject)
            }
        }

        return if (usePar) {
            submitPushedAuthorizationRequest(scopes, credentialAuthorizationRequestType, state)
        } else {
            authorizationRequestUrl(scopes, credentialAuthorizationRequestType, state)
        }
    }

    private suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        credentialAuthorizationRequestType: CredentialAuthorizationRequestType?,
        state: String,
    ): Result<Triple<PKCEVerifier, HttpsUrl, CredentialAuthorizationRequestType?>> = runCatching {
        require(scopes.isNotEmpty() || credentialAuthorizationRequestType != null) {
            "No scopes or authorization details provided. Cannot prepare authorization request."
        }

        val parEndpoint = pushedAuthorizationRequestEndpoint?.toURI()
        checkNotNull(parEndpoint) { "PAR endpoint not advertised" }
        val clientID = ClientID(cscClientConfig.client.clientId)
        val codeVerifier = CodeVerifier()
        val pushedAuthorizationRequest = run {
            val request = AuthorizationRequest.Builder(ResponseType.CODE, clientID).apply {
                redirectionURI(cscClientConfig.authFlowRedirectionURI)
                codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                state(State(state))
                if (scopes.isNotEmpty()) {
                    scope(NimbusScope(*scopes.map { it.value }.toTypedArray()))
                }
                if (credentialAuthorizationRequestType != null && credentialAuthorizationRequestType
                    is CredentialAuthorizationRequestType.PassByAuthorizationDetails
                ) {
                    authorizationDetails(
                        listOf(
                            credentialAuthorizationRequestType.credentialAuthorizationSubject.toNimbusAuthDetail(),
                        ),
                    )
                } else if (credentialAuthorizationRequestType != null &&
                    credentialAuthorizationRequestType is CredentialAuthorizationRequestType.PassByScope
                ) {
                    val subject = credentialAuthorizationRequestType.credentialAuthorizationSubject
                    when (subject.credentialRef) {
                        is CredentialRef.ByCredentialID -> customParameter(
                            "credentialID",
                            subject.credentialRef.credentialID.value,
                        )

                        is CredentialRef.BySignatureQualifier -> customParameter(
                            "signatureQualifier",
                            subject.credentialRef.signatureQualifier.value,
                        )
                    }
                    customParameter(
                        "hashes",
                        subject.documentDigestList?.documentDigests?.joinToString(",") {
                            it.hash.asBase64URLEncoded()
                        } ?: "",
                    )
                    customParameter(
                        "hashAlgorithmOID",
                        subject.documentDigestList?.hashAlgorithmOID?.value ?: "",
                    )
                    customParameter("numSignatures", subject.numSignatures.toString())
                }
                prompt(Prompt.Type.LOGIN)
            }.build()
            PushedAuthorizationRequest(parEndpoint, request)
        }
        val response = pushAuthorizationRequest(parEndpoint, pushedAuthorizationRequest, cscClientConfig.client)

        val (pkceVerifier, httpsUrl) = response.authorizationCodeUrlOrFail(clientID, codeVerifier, state)

        Triple(pkceVerifier, httpsUrl, credentialAuthorizationRequestType)
    }

    private fun PushedAuthorizationRequestResponseTO.authorizationCodeUrlOrFail(
        clientID: ClientID,
        codeVerifier: CodeVerifier,
        state: String,
    ): Pair<PKCEVerifier, HttpsUrl> = when (this) {
        is PushedAuthorizationRequestResponseTO.Success -> {
            val authorizationCodeUrl = run {
                val httpsUrl = URLBuilder(Url(authorizationEndpoint.toURI())).apply {
                    parameters.append(AuthorizationEndpointParams.PARAM_CLIENT_ID, clientID.value)
                    parameters.append(AuthorizationEndpointParams.PARAM_STATE, state)
                    parameters.append(AuthorizationEndpointParams.PARAM_REQUEST_URI, requestURI)
                }.build()
                HttpsUrl(httpsUrl.toString()).getOrThrow()
            }
            val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
            pkceVerifier to authorizationCodeUrl
        }

        is PushedAuthorizationRequestResponseTO.Failure -> throw RQESError.PushedAuthorizationRequestFailed(
            error,
            errorDescription,
        )
    }

    private suspend fun pushAuthorizationRequest(
        parEndpoint: URI,
        pushedAuthorizationRequest: PushedAuthorizationRequest,
        oauth2Client: OAuth2Client,
    ): PushedAuthorizationRequestResponseTO = ktorHttpClientFactory().use { client ->
        val url = parEndpoint.toURL()
        val formParameters = pushedAuthorizationRequest.asFormPostParams()

        val response = client.submitForm(
            url = url.toString(),
            formParameters = Parameters.build {
                formParameters.entries.forEach { (k, v) -> append(k, v) }
            },
        ) {
            if (oauth2Client is OAuth2Client.Confidential.ClientSecretBasic) {
                headers {
                    basicAuth(username = oauth2Client.clientId, password = oauth2Client.clientSecret)
                }
            }
        }
        if (response.status.isSuccess()) response.body<PushedAuthorizationRequestResponseTO.Success>()
        else response.body<PushedAuthorizationRequestResponseTO.Failure>()
    }

    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        authorizationRequest.toParameters().mapValues { (_, value) -> value[0] }.toMap()

    private fun authorizationRequestUrl(
        scopes: List<Scope>,
        credentialAuthorizationRequestType: CredentialAuthorizationRequestType?,
        state: String,
    ): Result<Triple<PKCEVerifier, HttpsUrl, CredentialAuthorizationRequestType?>> = runCatching {
        require(scopes.isNotEmpty() || credentialAuthorizationRequestType != null) {
            "No scopes or authorization details provided. Cannot prepare authorization request."
        }

        val clientID = ClientID(cscClientConfig.client.clientId)
        val codeVerifier = CodeVerifier()
        val authorizationRequest = AuthorizationRequest.Builder(ResponseType.CODE, clientID).apply {
            endpointURI(authorizationEndpoint.toURI())
            redirectionURI(cscClientConfig.authFlowRedirectionURI)
            codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            state(State(state))

            if (scopes.isNotEmpty()) {
                scope(NimbusScope(*scopes.map { it.value }.toTypedArray()))
            }

            if (credentialAuthorizationRequestType != null &&
                credentialAuthorizationRequestType is CredentialAuthorizationRequestType.PassByAuthorizationDetails
            ) {
                authorizationDetails(
                    listOf(
                        credentialAuthorizationRequestType.credentialAuthorizationSubject.toNimbusAuthDetail(),
                    ),
                )
            } else if (credentialAuthorizationRequestType != null &&
                credentialAuthorizationRequestType is CredentialAuthorizationRequestType.PassByScope
            ) {
                val subject = credentialAuthorizationRequestType.credentialAuthorizationSubject
                when (subject.credentialRef) {
                    is CredentialRef.ByCredentialID -> customParameter(
                        "credentialID",
                        subject.credentialRef.credentialID.value,
                    )

                    is CredentialRef.BySignatureQualifier -> customParameter(
                        "signatureQualifier",
                        subject.credentialRef.signatureQualifier.value,
                    )
                }
                customParameter(
                    "hashes",
                    subject.documentDigestList?.documentDigests?.joinToString(",") {
                        it.hash.asBase64URLEncoded()
                    } ?: "",
                )
                customParameter(
                    "hashAlgorithmOID",
                    subject.documentDigestList?.hashAlgorithmOID?.value ?: "",
                )
                customParameter("numSignatures", subject.numSignatures.toString())
            }

            prompt(Prompt.Type.LOGIN)
        }.build()

        val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
        val url = HttpsUrl(authorizationRequest.toURI().toString()).getOrThrow()
        Triple(pkceVerifier, url, credentialAuthorizationRequestType)
    }
}

private object AuthorizationEndpointParams {
    const val PARAM_CLIENT_ID = "client_id"
    const val PARAM_REQUEST_URI = "request_uri"
    const val PARAM_STATE = "state"
}

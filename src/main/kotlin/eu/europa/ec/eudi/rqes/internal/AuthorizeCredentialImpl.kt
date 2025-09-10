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
package eu.europa.ec.eudi.rqes.internal

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.AuthorizationError.InvalidAuthorizationState
import eu.europa.ec.eudi.rqes.internal.http.AuthorizationEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.CredentialInfoTO
import eu.europa.ec.eudi.rqes.internal.http.CredentialInfoTO.Success.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialsInfoEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointClient

internal class AuthorizeCredentialImpl(
    private val authorizationEndpointClient: AuthorizationEndpointClient?,
    private val tokenEndpointClient: TokenEndpointClient,
    private val credentialsInfoEndpointClient: CredentialsInfoEndpointClient,
) : AuthorizeCredential {

    override suspend fun prepareCredentialAuthorizationRequest(
        credentialAuthorizationSubject: CredentialAuthorizationSubject,
        walletState: String?,
    ): Result<CredentialAuthorizationRequestPrepared> = runCatching {
        checkNotNull(authorizationEndpointClient)

        require(credentialAuthorizationSubject.credentialRef is CredentialRef.ByCredentialID) {
            "Authorizing a credential by Signature Qualifier is not implemented yet"
        }

        val scopes = listOf(Scope(Scope.Credential.value))
        val state = walletState ?: State().value

        val (codeVerifier, authorizationCodeUrl, credentialAuthorizationSubjectMethod) =
            authorizationEndpointClient.submitParOrCreateAuthorizationRequestUrl(
                scopes,
                credentialAuthorizationSubject,
                state,
            ).getOrThrow()

        CredentialAuthorizationRequestPrepared(
            AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state),
            credentialAuthorizationSubjectMethod!!,
        )
    }

    private suspend fun getCredentialInfo(credentialID: CredentialID, accessToken: AccessToken): CredentialInfo {
        val credentialInfoTO = credentialsInfoEndpointClient.credentialInfo(
            CredentialsInfoRequest(credentialID),
            accessToken,
        ).getOrThrow()

        return when (credentialInfoTO) {
            is CredentialInfoTO.Success -> {
                credentialInfoTO.toDomain(credentialID)
            }
            else -> error("Unexpected response: $credentialInfoTO")
        }
    }

    override suspend fun CredentialAuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
        authDetailsOption: AccessTokenOption,
    ): Result<CredentialAuthorized> = runCatching {
        ensure(serverState == authorizationRequestPrepared.state) { InvalidAuthorizationState() }

        val tokenResponse =
            tokenEndpointClient.requestAccessTokenAuthFlow(
                authorizationCode,
                authorizationRequestPrepared.pkceVerifier,
                credentialAuthorizationRequestType,
            )

        val (accessToken, refreshToken, timestamp, credentialID, credentialAuthorizationSubject) = tokenResponse.getOrThrow()

        // TODO compare requested authorization with what was actually authorized
        val authorizedCredentialID = when {
            credentialAuthorizationSubject != null -> {
                require(credentialAuthorizationSubject.credentialRef is CredentialRef.ByCredentialID) {
                    "CredentialID was provided by the signing service"
                }
                credentialAuthorizationSubject.credentialRef.credentialID
            }
            credentialID != null -> {
                credentialID
            }
            credentialAuthorizationRequestType.credentialAuthorizationSubject.credentialRef
            is CredentialRef.ByCredentialID -> {
                (
                    credentialAuthorizationRequestType.credentialAuthorizationSubject.credentialRef
                        as CredentialRef.ByCredentialID
                    ).credentialID
            }
            else -> error("Credential ID is required")
        }

        val credential = getCredentialInfo(authorizedCredentialID, accessToken)

        when (credential.scal) {
            SCAL.One ->
                CredentialAuthorized.SCAL1(
                    OAuth2Tokens(accessToken, refreshToken, timestamp),
                    credential.credentialID,
                    credential.certificate,
                )

            SCAL.Two -> {
                requireNotNull(credentialAuthorizationRequestType.credentialAuthorizationSubject.documentDigestList) {
                    "Document list is required for SCAL 2"
                }
                CredentialAuthorized.SCAL2(
                    OAuth2Tokens(accessToken, refreshToken, timestamp),
                    credential.credentialID,
                    credential.certificate,
                    credentialAuthorizationRequestType.credentialAuthorizationSubject.documentDigestList!!,
                )
            }
        }
    }
}

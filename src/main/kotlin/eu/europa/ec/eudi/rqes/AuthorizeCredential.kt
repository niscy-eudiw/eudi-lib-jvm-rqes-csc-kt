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

data class CredentialAuthorizationRequestPrepared(
    val authorizationRequestPrepared: AuthorizationRequestPrepared,
    val credentialAuthorizationRequestType: CredentialAuthorizationRequestType,
)

sealed interface CredentialAuthorized : java.io.Serializable {

    val tokens: OAuth2Tokens
    val credentialID: CredentialID
    val credentialCertificate: CredentialCertificate

    data class SCAL1(
        override val tokens: OAuth2Tokens,
        override val credentialID: CredentialID,
        override val credentialCertificate: CredentialCertificate,
    ) : CredentialAuthorized

    data class SCAL2(
        override val tokens: OAuth2Tokens,
        override val credentialID: CredentialID,
        override val credentialCertificate: CredentialCertificate,
        val documentDigestList: DocumentDigestList,
    ) : CredentialAuthorized
}

sealed interface AccessTokenOption {

    data object AsRequested : AccessTokenOption
}

interface AuthorizeCredential {

    /**
     * Initial step for the credential authorization process using the Authorization code flow.
     * @param credentialAuthorizationSubject the subject of the credential authorization request
     * @param walletState an optional parameter that if provided will be included in the authorization request.
     * If it is not provided,  a random value will be used
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @return an HTTPS URL of the authorization request to be placed
     */
    suspend fun ServiceAccessAuthorized.prepareCredentialAuthorizationRequest(
        credentialAuthorizationSubject: CredentialAuthorizationSubject,
        walletState: String? = null,
    ): Result<CredentialAuthorizationRequestPrepared>

    /**
     * Using the access code retrieved after performing the authorization request prepared from a call to
     * [AuthorizeService.prepareServiceAuthorizationRequest()], it posts a request to authorization server's token endpoint to
     * retrieve an access token. This step transitions state from [CredentialAuthorizationRequestPrepared] to a
     * [CredentialAuthorized] state
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     * @param serverState The state returned from authorization server via front-channel
     * @return an issuance request in authorized state
     */
    suspend fun CredentialAuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
        authDetailsOption: AccessTokenOption = AccessTokenOption.AsRequested,
    ): Result<CredentialAuthorized>
}

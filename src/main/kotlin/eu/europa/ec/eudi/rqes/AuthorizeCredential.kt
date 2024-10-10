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

@JvmInline
value class CredentialAuthorizationRequestPrepared(val value: AuthorizationRequestPrepared)

sealed interface CredentialAuthorized : java.io.Serializable {

    val tokens: OAuth2Tokens
    val credentialID: CredentialID

    data class SCAL1(
        override val tokens: OAuth2Tokens,
        override val credentialID: CredentialID,
    ) : CredentialAuthorized

    data class SCAL2(
        override val tokens: OAuth2Tokens,
        override val credentialID: CredentialID,
        val documentList: DocumentList,
    ) : CredentialAuthorized
}

interface AuthorizeCredential {

    /**
     * Initial step for the credential authorization process using the Authorization code flow.
     * @param credential the credential to be authorized
     * @param documentList the list of documents for which the credential is to be authorized
     * @param numSignatures the number of signatures to be authorized for the credential
     * @param walletState an optional parameter that if provided will be included in the authorization request.
     * If it is not provided,  a random value will be used
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @return an HTTPS URL of the authorization request to be placed
     */
    suspend fun ServiceAccessAuthorized.prepareCredentialAuthorizationRequest(
        credential: CredentialInfo,
        documentList: DocumentList?,
        numSignatures: Int? = 1,
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
    ): Result<CredentialAuthorized>
}

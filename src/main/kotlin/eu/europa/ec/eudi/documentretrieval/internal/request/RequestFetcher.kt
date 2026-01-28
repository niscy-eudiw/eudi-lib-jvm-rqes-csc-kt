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
package eu.europa.ec.eudi.documentretrieval.internal.request

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.rqes.internal.ensure
import eu.europa.ec.eudi.rqes.internal.ensureNotNull
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import java.net.URL
import java.text.ParseException

internal class RequestFetcher(
    private val httpClient: HttpClient,
    private val documentRetrievalConfig: DocumentRetrievalConfig,
) {
    /**
     * Fetches the authorization request, if needed
     */
    suspend fun fetchRequest(request: UnvalidatedRequest): FetchedRequest {
        val (jwt, walletNonce) = fetchJwtAndWalletNonce(request)
        with(documentRetrievalConfig) {
            return ensureValid(expectedClient = request.clientId, expectedWalletNonce = walletNonce, unverifiedJwt = jwt)
        }
    }

    private suspend fun fetchJwtAndWalletNonce(
        request: UnvalidatedRequest,
    ): Pair<Jwt, Nonce?> {
        val (_, requestUri) = request
        return httpClient.getJAR(requestUri) to null
    }
}

private suspend fun HttpClient.getJAR(requestUri: URL): Jwt =
    get(requestUri) { addAcceptContentTypeJwt() }.body()

private const val APPLICATION_JWT = "application/jwt"
private const val APPLICATION_OAUTH_AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt"

private fun HttpRequestBuilder.addAcceptContentTypeJwt() {
    accept(ContentType.parse(APPLICATION_OAUTH_AUTHZ_REQ_JWT))
    accept(ContentType.parse(APPLICATION_JWT))
}

private fun DocumentRetrievalConfig.ensureValid(
    expectedClient: String,
    expectedWalletNonce: Nonce?,
    unverifiedJwt: Jwt,
): FetchedRequest {
    val signedJwt = ensureIsSignedJwt(unverifiedJwt).also(::ensureSupportedSigningAlgorithm)
    val clientId = ensureSameClientId(expectedClient, signedJwt)
    if (expectedWalletNonce != null) {
        ensureSameWalletNonce(expectedWalletNonce, signedJwt)
    }
    return FetchedRequest(clientId, signedJwt)
}

private fun ensureIsSignedJwt(unverifiedJwt: Jwt): SignedJWT =
    try {
        SignedJWT.parse(unverifiedJwt)
    } catch (_: ParseException) {
        throw invalidJwt("JAR JWT parse error")
    }

private fun ensureSameWalletNonce(expectedWalletNonce: Nonce, signedJwt: SignedJWT) {
    val walletNonce = signedJwt.jwtClaimsSet.getStringClaim("wallet_nonce")
    ensure(expectedWalletNonce.toString() == walletNonce) {
        invalidJwt("Mismatch of wallet_nonce. Expected $expectedWalletNonce, actual $walletNonce")
    }
}

private fun DocumentRetrievalConfig.ensureSupportedSigningAlgorithm(signedJwt: SignedJWT) {
    val signingAlg = ensureNotNull(signedJwt.header.algorithm) {
        invalidJwt("JAR is missing alg claim from header")
    }
    ensure(signingAlg in jarConfiguration.supportedAlgorithms) {
        invalidJwt("JAR is signed with ${signingAlg.name} which is not supported")
    }
}

private fun ensureSameClientId(
    expectedClientId: String,
    signedJwt: SignedJWT,
): String {
    val jarClientId = signedJwt.jwtClaimsSet.getStringClaim("client_id")
    ensure(expectedClientId == jarClientId) {
        invalidJwt("ClientId mismatch. JAR request $expectedClientId, jwt $jarClientId")
    }
    return expectedClientId
}

private fun invalidJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

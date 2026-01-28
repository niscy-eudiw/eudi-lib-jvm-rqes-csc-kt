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
package eu.europa.ec.eudi.documentretrieval.internal.response

import eu.europa.ec.eudi.documentretrieval.AuthorizationRequestError
import eu.europa.ec.eudi.documentretrieval.Consensus
import eu.europa.ec.eudi.documentretrieval.Resolution
import eu.europa.ec.eudi.documentretrieval.ResolvedRequestObject
import eu.europa.ec.eudi.documentretrieval.ResponseMode
import java.io.Serializable
import java.net.URL

/**
 * The payload of an [AuthorizationResponse]
 */
internal sealed interface AuthorizationResponsePayload : Serializable {

    val nonce: String?
    val state: String?
    val clientId: String

    data class Success(
        override val nonce: String?,
        override val state: String?,
        override val clientId: String,
        val documentWithSignature: List<String>?,
        val signatureObject: List<String>?,
    ) : AuthorizationResponsePayload

    sealed interface Failed : AuthorizationResponsePayload

    /**
     * In response of an [Resolution.Invalid] authorization request
     * @param error the cause
     * @param state the state of the request
     */
    data class InvalidRequest(
        val error: AuthorizationRequestError,
        override val nonce: String,
        override val state: String?,
        override val clientId: String,
    ) : Failed

    /**
     * In response of a [ResolvedRequestObject] and
     * holder's [negative consensus][Consensus.Negative]
     * @param state the state of the [request][ResolvedRequestObject.state]
     */
    data class NoConsensusResponseData(
        override val nonce: String?,
        override val state: String?,
        override val clientId: String,
    ) : Failed
}

/**
 * An OAUTH2 authorization response
 */
internal sealed interface AuthorizationResponse : Serializable {

    /**
     * An authorization response to be communicated to verifier/RP via direct_post method
     *
     * @param responseUri the verifier/RP URI where the response will be posted
     * @param data the contents of the authorization response
     */
    data class DirectPost(
        val responseUri: URL,
        val data: AuthorizationResponsePayload,
    ) : AuthorizationResponse
}

internal fun ResolvedRequestObject.responseWith(
    consensus: Consensus,
): AuthorizationResponse {
    val payload = responsePayload(consensus)
    return responseWith(payload)
}

private fun ResolvedRequestObject.responsePayload(
    consensus: Consensus,
): AuthorizationResponsePayload = when (consensus) {
    is Consensus.Negative -> AuthorizationResponsePayload.NoConsensusResponseData(nonce, state, client.id)
    is Consensus.Positive -> AuthorizationResponsePayload.Success(
        nonce,
        state,
        client.id,
        consensus.documentWithSignature,
        consensus.signatureObject,
    )
}

private fun ResolvedRequestObject.responseWith(
    data: AuthorizationResponsePayload,
): AuthorizationResponse {
    return when (val mode = responseMode) {
        is ResponseMode.DirectPost -> AuthorizationResponse.DirectPost(mode.responseURI, data)
    }
}

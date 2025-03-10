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
package eu.europa.ec.eudi.documentretrieval.internal.request

import com.eygraber.uri.Uri
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.rqes.KtorHttpClientFactory
import io.ktor.client.*
import io.ktor.client.plugins.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import java.net.URL

/**
 * The data of a Document Retrieval authorization request
 * without any validation and regardless of the way they sent to the wallet
 */
@Serializable
internal data class UnvalidatedRequestObject(
    @SerialName("response_type") val responseType: String? = null,
    @SerialName("client_id") val clientId: String? = null,
    @SerialName("client_id_scheme") val clientIdScheme: String? = null,
    @SerialName("response_mode") val responseMode: String? = null,
    @SerialName("response_uri") val responseUri: String? = null,
    @SerialName("nonce") val nonce: String? = null,
    @SerialName("state") val state: String? = null,
    @SerialName("signatureQualifier") val signatureQualifier: String? = null,
    @SerialName("documentDigests") val documentDigests: JsonArray? = null,
    @SerialName("documentLocations") val documentLocations: JsonArray? = null,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String? = null,
    @SerialName("clientData") val clientData: String? = null,
)

/**
 * authorization request
 *
 * This is merely a data carrier structure that doesn't enforce any rules.
 */
data class UnvalidatedRequest(
    val clientId: String,
    val jwtURI: URL,
) {

    companion object {
        /**
         * Convenient method for parsing a URI representing an OAUTH2 Authorization request.
         */
        fun make(uriStr: String): Result<UnvalidatedRequest> = runCatching {
            val uri = Uri.parse(uriStr)
            fun clientId(): String =
                uri.getQueryParameter("client_id")
                    ?: throw RequestValidationError.MissingClientId.asException()
            val requestUriValue = uri.getQueryParameter("request_uri")
                ?: throw RequestValidationError.MissingRequestUri.asException()

            val requestUri = requestUriValue.asURL().getOrThrow()
            UnvalidatedRequest(clientId(), requestUri)
        }
    }
}

data class FetchedRequest(val clientId: String, val jwt: SignedJWT)

internal class DefaultAuthorizationRequestResolver(
    private val documentRetrievalConfig: DocumentRetrievalConfig,
    private val httpKtorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizationRequestResolver {

    override suspend fun resolveRequestUri(uri: String): Resolution =
        httpKtorHttpClientFactory().use { httpClient ->
            resolveRequestUri(httpClient, uri)
        }

    private suspend fun resolveRequestUri(httpClient: HttpClient, uri: String): Resolution {
        val requestFetcher = RequestFetcher(httpClient, documentRetrievalConfig)
        val requestAuthenticator = RequestAuthenticator(documentRetrievalConfig, httpClient)

        return try {
            val unvalidatedRequest = UnvalidatedRequest.make(uri).getOrThrow()
            val fetchedRequest = requestFetcher.fetchRequest(unvalidatedRequest)
            val authenticatedRequest = requestAuthenticator.authenticate(fetchedRequest)
            val resolveRequestObject = validateRequestObject(authenticatedRequest)
            Resolution.Success(resolveRequestObject)
        } catch (e: AuthorizationRequestException) {
            Resolution.Invalid(e.error)
        } catch (e: ClientRequestException) {
            Resolution.Invalid(HttpError(e))
        }
    }
}

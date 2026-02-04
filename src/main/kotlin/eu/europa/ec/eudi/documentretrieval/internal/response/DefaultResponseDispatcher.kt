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

import eu.europa.ec.eudi.documentretrieval.Consensus
import eu.europa.ec.eudi.documentretrieval.DispatchOutcome
import eu.europa.ec.eudi.documentretrieval.Dispatcher
import eu.europa.ec.eudi.documentretrieval.ResolvedRequestObject
import eu.europa.ec.eudi.documentretrieval.internal.response.AuthorizationResponse.DirectPost
import eu.europa.ec.eudi.rqes.KtorHttpClientFactory
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URL
import java.util.Base64

/**
 * Default implementation of [Dispatcher]
 *
 * @param httpClientFactory factory to obtain [HttpClient]
 */
internal class DefaultDispatcher(
    private val httpClientFactory: KtorHttpClientFactory,
) : Dispatcher {

    override suspend fun dispatch(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ): DispatchOutcome {
        val (responseUri, parameters) = formParameters(request, consensus)
        return httpClientFactory().use { httpClient ->
            submitForm(httpClient, responseUri, parameters)
        }
    }

    private fun formParameters(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ) =
        when (val response = request.responseWith(consensus)) {
            is DirectPost -> {
                val parameters = DirectPostForm.parametersOf(response.data)
                response.responseUri to parameters
            }
        }

    /**
     * Submits an HTTP Form to [url] with the provided [parameters].
     */
    @OptIn(InternalAPI::class)
    private suspend fun submitForm(
        httpClient: HttpClient,
        url: URL,
        parameters: Parameters,
    ): DispatchOutcome {
        val response = httpClient.post(url.toExternalForm()) {
            body = FormData(parameters)
        }

        return when (response.status) {
            HttpStatusCode.OK -> {
                val redirectUri =
                    try {
                        response.body<JsonObject?>()
                            ?.get("redirect_uri")
                            ?.takeIf { it is JsonPrimitive }
                            ?.jsonPrimitive?.contentOrNull
                            ?.let { URI.create(it) }
                    } catch (_: NoTransformationFoundException) {
                        null
                    }
                DispatchOutcome.Accepted(redirectUri)
            }

            else -> DispatchOutcome.Rejected
        }
    }
}

/**
 * An object responsible for encoding a [AuthorizationResponsePayload] into
 * HTTP form
 */
internal object DirectPostForm {

    private const val DOCUMENT_WITH_SIGNATURE = "documentWithSignature"
    private const val SIGNATURE_OBJECT = "signatureObject"
    private const val STATE_FORM_PARAM = "state"
    private const val ERROR_FORM_PARAM = "error"

    fun parametersOf(p: AuthorizationResponsePayload): Parameters =
        of(p).let { form ->
            parameters {
                form.entries.forEach { (name, value) -> append(name, value) }
            }
        }

    fun of(p: AuthorizationResponsePayload): Map<String, String> {
        fun MutableMap<String, String>.putDocumentWithSignature(documentWithSignature: List<ByteArray>) {
            put(DOCUMENT_WITH_SIGNATURE, documentWithSignature.map { Base64.getEncoder().encode(it).decodeToString() }.asParam())
        }

        fun MutableMap<String, String>.putSignatureObject(signatureObject: List<String>) {
            put(SIGNATURE_OBJECT, signatureObject.asParam())
        }

        return when (p) {
            is AuthorizationResponsePayload.Success -> buildMap {
                p.documentWithSignature?.let {
                    putDocumentWithSignature(it)
                }
                p.signatureObject?.let {
                    putSignatureObject(it)
                }
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.InvalidRequest -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.fromError(p.error).code)
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }

            is AuthorizationResponsePayload.NoConsensusResponseData -> buildMap {
                put(ERROR_FORM_PARAM, AuthorizationRequestErrorCode.USER_CANCELLED.code)
                p.state?.let {
                    put(STATE_FORM_PARAM, it)
                }
            }
        }
    }
}

internal fun List<String>.asParam() =
    buildJsonArray {
        forEach { add(it) }
    }.run(Json::encodeToString)

/**
 * [OutgoingContent] for `application/x-www-form-urlencoded` formatted requests that use US-ASCII encoding.
 */
internal class FormData(
    formData: Parameters,
) : OutgoingContent.ByteArrayContent() {
    private val content = formData.formUrlEncode().toByteArray(Charsets.US_ASCII)

    override val contentLength: Long = content.size.toLong()
    override val contentType: ContentType = ContentType.Application.FormUrlEncoded

    override fun bytes(): ByteArray = content
}

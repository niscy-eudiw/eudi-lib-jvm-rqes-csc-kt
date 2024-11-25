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

import eu.europa.ec.eudi.rqes.internal.http.AuthorizationDetailTO
import eu.europa.ec.eudi.rqes.internal.http.PushedAuthorizationRequestResponseTO
import eu.europa.ec.eudi.rqes.internal.http.TokenResponseTO
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.*

internal fun credentialIssuerMetaDataHandler(id: RSSPId, resource: String): RequestMocker = RequestMocker(
    match(id.info().value.toURI(), HttpMethod.Post),
    jsonResponse(resource),
)

internal fun authServerWellKnownMocker(): RequestMocker = RequestMocker(
    requestMatcher = endsWith("/.well-known/openid-configuration", HttpMethod.Get),
    responseBuilder = {
        respond(
            content = getResourceAsText("well-known/openid-configuration.json"),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    },
)

internal fun parPostMocker(parEndpoint: String, validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith(parEndpoint, HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    PushedAuthorizationRequestResponseTO.Success(
                        "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                        3600,
                    ),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun tokenPostMocker(
    authorizationDetails: List<AuthorizationDetailTO>? = null,
    validator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    TokenResponseTO.Success(
                        accessToken = UUID.randomUUID().toString(),
                        expiresIn = 3600,
                        authorizationDetails = authorizationDetails,
                    ),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun credentialsListPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/credentials/list", HttpMethod.Post),
        responseBuilder = {
            val content = getResourceAsText("eu/europa/ec/eudi/rqes/internal/credentials_list_valid.json")
            respond(
                content = content,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun credentialsInfoPostMocker(
    resource: String = "eu/europa/ec/eudi/rqes/internal/credentials_info_scal2_oauth_valid.json",
    validator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/credentials/info", HttpMethod.Post),
        responseBuilder = {
            val content = getResourceAsText(resource)
            respond(
                content = content,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun calculateHashPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/signatures/calculate_hash", HttpMethod.Post),
        responseBuilder = {
            val content = getResourceAsText("eu/europa/ec/eudi/rqes/internal/calculate_hash_valid.json")
            respond(
                content = content,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun obtainSignedDocPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/signatures/obtain_signed_doc", HttpMethod.Post),
        responseBuilder = {
            val content = getResourceAsText("eu/europa/ec/eudi/rqes/internal/obtain_signed_doc_valid.json")
            respond(
                content = content,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun signHashPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/signatures/signHash", HttpMethod.Post),
        responseBuilder = {
            val content = getResourceAsText("eu/europa/ec/eudi/rqes/internal/sign_hash_valid.json")
            respond(
                content = content,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

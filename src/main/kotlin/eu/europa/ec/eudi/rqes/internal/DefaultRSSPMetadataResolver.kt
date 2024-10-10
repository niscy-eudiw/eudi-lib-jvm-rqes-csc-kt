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

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.http.RSSPMetadataJsonParser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI
import java.util.*

sealed interface ValidatedAuthType {
    data object External : ValidatedAuthType
    data object Basic : ValidatedAuthType
    data object Digest : ValidatedAuthType
    data object TLS : ValidatedAuthType
    data class OAuth2(
        val oauth2Issuer: HttpsUrl? = null,
        val oauth2: HttpsUrl? = null,
        val grantsTypes: Set<Oauth2Grant>,
    ) : ValidatedAuthType {
        init {
            require(grantsTypes.isNotEmpty()) { "At least one GrantType must be provided" }
            require(oauth2Issuer != null || oauth2 != null) { "At least one of oauth2Issuer or oauth2 must be provided" }
        }
    }
}

internal data class ValidatedRSSPMetadata(
    val specs: String,
    val name: String,
    val logo: URI,
    val region: String,
    val lang: Locale,
    val description: String,
    val authTypes: Set<ValidatedAuthType>,
    val asynchronousOperationMode: Boolean? = false,
    val methods: List<RSSPMethod>,
    val validationInfo: Boolean? = false,
)

internal class DefaultRSSPMetadataResolver(private val httpClient: HttpClient) : RSSPMetadataResolver {
    override suspend fun resolve(rsspId: RSSPId, lang: Locale?): Result<RSSPMetadata> = runCatching {
        val json: String = try {
            httpClient.post(rsspId.info()) {
                contentType(ContentType.Application.Json)
                setBody(
                    buildJsonObject {
                        lang?.let { put("lang", it.toLanguageTag()) }
                    },
                )
            }.body()
        } catch (t: Throwable) {
            throw RSSPMetadataError.UnableToFetchRSSPMetadata(t)
        }

        val validated = RSSPMetadataJsonParser.parseMetaData(json)
        resolveOauth2Meta(rsspId, validated)
    }

    private suspend fun resolveOauth2Meta(
        rsspId: RSSPId,
        validatedRSSPMetadata: ValidatedRSSPMetadata,
    ): RSSPMetadata {
        return RSSPMetadata(
            rsspId = rsspId,
            specs = validatedRSSPMetadata.specs,
            name = validatedRSSPMetadata.name,
            logo = validatedRSSPMetadata.logo,
            region = validatedRSSPMetadata.region,
            lang = validatedRSSPMetadata.lang,
            methods = validatedRSSPMetadata.methods,
            asynchronousOperationMode = validatedRSSPMetadata.asynchronousOperationMode,
            validationInfo = validatedRSSPMetadata.validationInfo,
            description = validatedRSSPMetadata.description,
            authTypes = validatedRSSPMetadata.authTypes.map { authType ->
                when (authType) {
                    ValidatedAuthType.Basic -> AuthType.Basic
                    ValidatedAuthType.Digest -> AuthType.Digest
                    ValidatedAuthType.External -> AuthType.External
                    ValidatedAuthType.TLS -> AuthType.TLS
                    is ValidatedAuthType.OAuth2 -> resolveOauth2(authType, validatedRSSPMetadata.methods)
                }
            }.let { types -> AuthTypesSupported(types.toSet()) },
        )
    }

    private suspend fun resolveOauth2(authType: ValidatedAuthType.OAuth2, methods: List<RSSPMethod>): AuthType.OAuth2 {
        val (oauth2Issuer, oauth2, grants) = authType
        val meta = when {
            oauth2Issuer != null -> DefaultAuthorizationServerMetadataResolver(httpClient).resolve(oauth2Issuer).getOrThrow()
            oauth2 != null -> asMetadata(oauth2, methods)
            else -> error("Cannot happen")
        }
        return AuthType.OAuth2(meta, grants)
    }
}

internal fun asMetadata(
    oauth2Url: HttpsUrl,
    methods: List<RSSPMethod>,
): ReadOnlyAuthorizationServerMetadata {
    val issuer = Issuer(oauth2Url.toString())
    val meta = AuthorizationServerMetadata(issuer).apply {
        tokenEndpointURI = URI("$oauth2Url/token")
        if (RSSPMethod.Oauth2Authorize in methods) {
            authorizationEndpointURI = URI("$oauth2Url/authorize")
            if (RSSPMethod.Oauth2PushedAuthorize in methods) {
                pushedAuthorizationRequestEndpointURI = URI("$oauth2Url/pushed_authorize")
            }
        }
        if (RSSPMethod.Oauth2Revoke in methods) {
            revocationEndpointURI = URI("$oauth2Url/revoke")
        }
    }
    return object : ReadOnlyAuthorizationServerMetadata by meta {}
}

private fun RSSPId.info() = URLBuilder(Url(value.value.toURI()))
    .appendPathSegments("/info", encodeSlash = false)
    .build()
    .toURI()
    .toURL()

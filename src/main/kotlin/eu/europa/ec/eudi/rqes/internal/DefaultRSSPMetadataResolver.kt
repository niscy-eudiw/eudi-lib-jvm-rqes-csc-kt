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
package eu.europa.ec.eudi.rqes.internal

import com.nimbusds.oauth2.sdk.GrantType
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

internal sealed interface AuthorizationServerRef {
    data class IssuerClaim(val value: HttpsUrl, val grants: List<String>, val supportsRar: Boolean) : AuthorizationServerRef

    data class CSCAuth2Claim(val value: HttpsUrl, val grants: List<String>, val supportsRar: Boolean) : AuthorizationServerRef
}

internal class DefaultRSSPMetadataResolver(
    private val httpClient: HttpClient,
) : RSSPMetadataResolver {

    override suspend fun resolve(rsspId: RSSPId, lang: Locale?): Result<RSSPMetadata> =
        runCatching {
            val metadataInJson = fetchMetadata(rsspId, lang)
            val contents = RSSPMetadataJsonParser.parseMetaData(rsspId, metadataInJson)
            val resolved = contents.map {
                    serverRef ->
                fetchAuthorizationServerMetadata(serverRef)
            }
            resolved
        }

    private suspend fun fetchMetadata(rsspId: RSSPId, lang: Locale?): String =
        try {
            httpClient.post(rsspId.info()) {
                contentType(ContentType.Application.Json)
                setBody(
                    buildJsonObject {
                        lang?.let { put("lang", it.toLanguageTag()) }
                    },
                )
            }.body<String>()
        } catch (t: Throwable) {
            throw RSSPMetadataError.UnableToFetchRSSPMetadata(t)
        }

    private suspend fun fetchAuthorizationServerMetadata(
        serverRef: AuthorizationServerRef,
    ): CSCAuthorizationServerMetadata = when (serverRef) {
        is AuthorizationServerRef.IssuerClaim ->
            DefaultAuthorizationServerMetadataResolver(httpClient).resolve(serverRef.value).getOrThrow()

        is AuthorizationServerRef.CSCAuth2Claim ->
            asMetadata(serverRef.value)
    }
}

internal fun asMetadata(
    oauth2Url: HttpsUrl,
): CSCAuthorizationServerMetadata {
    val issuer = Issuer(oauth2Url.toString())
    val meta = AuthorizationServerMetadata(issuer).apply {
        tokenEndpointURI = URI("$oauth2Url/oauth2/token")
        authorizationEndpointURI = URI("$oauth2Url/oauth2/authorize")
        pushedAuthorizationRequestEndpointURI = URI("$oauth2Url/oauth2/pushed_authorize")
        revocationEndpointURI = URI("$oauth2Url/revoke")
        grantTypes = listOf(GrantType.AUTHORIZATION_CODE)
    }
    return object : ReadOnlyAuthorizationServerMetadata by meta {}
}

private fun RSSPId.info() = URLBuilder(Url(value.value.toURI()))
    .appendPathSegments("/info", encodeSlash = false)
    .build()
    .toURI()
    .toURL()

internal inline fun <reified T, reified Y> RSSPMetadataContent<T>.map(f: (T) -> Y): RSSPMetadataContent<Y> {
    val authTypes = authTypes.map { authType -> authType.map { f(it) } }.toSet()

    return RSSPMetadataContent(
        rsspId = rsspId,
        specs = specs,
        name = name,
        logo = logo,
        region = region,
        lang = lang,
        methods = methods,
        asynchronousOperationMode = asynchronousOperationMode,
        validationInfo = validationInfo,
        description = description,
        authTypes = authTypes,
    )
}

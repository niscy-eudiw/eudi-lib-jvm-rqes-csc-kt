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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.AuthorizationServerRef
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

internal object RSSPMetadataJsonParser {
    fun parseMetaData(rsspId: RSSPId, json: String): RSSPMetadataContent<AuthorizationServerRef> {
        val parsed = parseJson(json)
        return contents(rsspId, parsed)
    }
}

@Serializable
private data class RSSPMetadataTO(
    @SerialName("specs") val specs: String? = null,
    @SerialName("name") val name: String? = null,
    @SerialName("logo") val logo: String? = null,
    @SerialName("region") val region: String? = null,
    @SerialName("lang") val lang: String? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("authType") @Required val authTypes: List<String>,
    @SerialName("oauth2Servers") val oauth2Servers: List<OAuth2Server>? = null,
    @SerialName("oauth2") val oauth2: String? = null,
    @SerialName("oauth2Issuer") val oauth2Issuer: String? = null,
    @SerialName("supportsRar") val supportsRar: Boolean? = false,
    @SerialName("supportedHashTypes") val supportedHashTypes: List<String>? = null,
    @SerialName("asynchronousOperationMode") val asynchronousOperationMode: Boolean? = false,
    @SerialName("methods") @Required val methods: List<String>,
    @SerialName("validationInfo") val validationInfo: Boolean? = false,
    @SerialName("signAlgorithms") @Required val signAlgorithms: SignAlgorithms,
    @SerialName("documentTypes") val documentTypes: List<String>? = null,
    @SerialName("signature_formats") @Required val signatureFormats: SignatureFormats,
    @SerialName("conformance_levels") val conformanceLevels: List<String>? = null,
)

@Serializable
private data class OAuth2Server(
    @SerialName("label") val label: String? = null,
    @SerialName("baseUri") val baseUri: String? = null,
    @SerialName("issuerIdentifier") val issuerIdentifier: String? = null,
    @SerialName("authType") @Required val authType: List<String>,
    @SerialName("supportsRar") val supportsRar: Boolean? = false,
)

@Serializable
private data class SignAlgorithms(
    @SerialName("algos") @Required val algos: List<String>,
    @SerialName("algoParams") val algoParams: List<String?>? = null,
)

@Serializable
private data class SignatureFormats(
    @SerialName("formats") @Required val formats: List<String>,
    @SerialName("envelope_properties") val envelopeProperties: List<List<String>>? = null,
    @SerialName("allowMix") val allowMix: Boolean? = false,
)

private fun parseJson(json: String): RSSPMetadataTO =
    try {
        JsonSupport.decodeFromString<RSSPMetadataTO>(json)
    } catch (t: Throwable) {
        throw RSSPMetadataError.NonParseableRSSPMetadata(t)
    }

private fun contents(rsspId: RSSPId, metadata: RSSPMetadataTO): RSSPMetadataContent<AuthorizationServerRef> {
    val authTypesSupported = authTypesSupported(metadata)
    val logo = metadata.logo?.let { runCatching { URI.create(it) }.getOrNull() }
    val lang = localeOf(metadata)
    val methods = metadata.methods.mapNotNull { RSSPMethod.from(it) }
    return RSSPMetadataContent(
        rsspId = rsspId,
        specs = metadata.specs,
        name = metadata.name,
        logo = logo,
        region = metadata.region,
        lang = lang,
        description = metadata.description,
        authTypes = authTypesSupported,
        asynchronousOperationMode = metadata.asynchronousOperationMode ?: false,
        methods = methods,
        validationInfo = metadata.validationInfo ?: false,
    )
}

private fun localeOf(metadata: RSSPMetadataTO): Locale? =
    metadata.lang?.let { tag ->
        runCatching { Locale.forLanguageTag(tag) }.getOrNull()
    }

internal fun RSSPMethod.Companion.from(s: String): RSSPMethod? = when (s) {
    "info" -> RSSPMethod.Info
    "auth/login" -> RSSPMethod.AuthLogin
    "auth/revoke" -> RSSPMethod.AuthRevoke
    "credentials/list" -> RSSPMethod.CredentialsList
    "credentials/info" -> RSSPMethod.CredentialsInfo
    "credentials/authorize" -> RSSPMethod.CredentialsAuthorize
    "credentials/authorizeCheck" -> RSSPMethod.CredentialsAuthorizeCheck
    "credentials/getChallenge" -> RSSPMethod.CredentialsGetChallenge
    "credentials/sendOTP" -> RSSPMethod.CredentialsSendOTP
    "credentials/extendTransaction" -> RSSPMethod.CredentialsExtendTransaction
    "credentials/create" -> RSSPMethod.CredentialsCreate
    "credentials/delete" -> RSSPMethod.CredentialsDelete
    "signatures/signHash" -> RSSPMethod.SignaturesSignHash
    "signatures/signDoc" -> RSSPMethod.SignaturesSignDoc
    "signatures/signPolling" -> RSSPMethod.SignaturesSignPolling
    "signatures/timestamp" -> RSSPMethod.SignaturesTimestamp
    else -> null
}

private fun authTypesSupported(metadata: RSSPMetadataTO): Set<AuthType<AuthorizationServerRef>> {
    val authTypes = buildSet {
        metadata.authTypes.forEach { authType ->
            when (authType) {
                "external" -> add(AuthType.External)
                "tls" -> add(AuthType.TLS)
                "basic" -> add(AuthType.Basic)
                "digest" -> add(AuthType.Digest)
                else -> {
                    // Do nothing
                }
            }
        }

        metadata.oauth2Servers?.let { servers ->
            val authServerRefs = servers.mapNotNull { server ->
                authServerRefFromOAuth2Server(server)
            }.toSet()
            add(AuthType.OAuth2(authServerRefs))
        } ?: run {
            val grants = grantTypesOf(metadata)
            if (grants.isNotEmpty()) {
                val authServerRef = authServerRef(metadata)
                requireNotNull(authServerRef) {
                    "When authTypes $OAUTH2_CLIENT and/or $OAUTH2_CODE are provided one of oauth2Issuer or oauth2 is expected"
                }
                add(AuthType.OAuth2(setOf(authServerRef)))
            }
        }
    }

    return authTypes
}

private fun authServerRef(metadata: RSSPMetadataTO): AuthorizationServerRef? {
    val issuerClaim = metadata.oauth2Issuer
    val oauth2Claim = metadata.oauth2

    require(issuerClaim != null || oauth2Claim != null) { "issuerClaim or oauth2Claim must be set" }
    require(!(issuerClaim != null && oauth2Claim != null)) { "issuerClaim and oauth2Claim cannot both be set" }

    val grants = metadata.authTypes.filter { it in listOf(OAUTH2_CLIENT, OAUTH2_CODE) }

    fun urlOrNull(s: String, grants: List<String>, supportsRar: Boolean, f: (HttpsUrl, List<String>, Boolean) -> AuthorizationServerRef) =
        HttpsUrl(s).getOrNull()?.let { f(it, grants, supportsRar) }

    return when {
        issuerClaim != null -> urlOrNull(issuerClaim, grants, metadata.supportsRar ?: false, AuthorizationServerRef::IssuerClaim)
        oauth2Claim != null -> urlOrNull(oauth2Claim, grants, metadata.supportsRar ?: false, AuthorizationServerRef::CSCAuth2Claim)
        else -> null
    }
}

private fun authServerRefFromOAuth2Server(server: OAuth2Server): AuthorizationServerRef? {
    // require issuerIdentifier or baseUri to be set, but not both
    require(server.issuerIdentifier != null || server.baseUri != null) { "issuerIdentifier or baseUri must be set" }
    require(!(server.issuerIdentifier != null && server.baseUri != null)) { "issuerIdentifier and baseUri cannot both be set" }

    fun urlOrNull(s: String, grants: List<String>, supportsRar: Boolean, f: (HttpsUrl, List<String>, Boolean) -> AuthorizationServerRef) =
        HttpsUrl(s).getOrNull()?.let { f(it, grants, supportsRar) }

    return when {
        server.issuerIdentifier != null -> urlOrNull(
            server.issuerIdentifier,
            server.authType,
            server.supportsRar ?: false,
            AuthorizationServerRef::IssuerClaim,
        )
        else -> urlOrNull(server.baseUri!!, server.authType, server.supportsRar ?: false, AuthorizationServerRef::CSCAuth2Claim)
    }
}

private const val OAUTH2_CODE = "oauth2code"
private const val OAUTH2_CLIENT = "oauth2client"

private fun grantTypesOf(metadata: RSSPMetadataTO): Set<Oauth2Grant> =
    buildSet {
        if (OAUTH2_CODE in metadata.authTypes) {
            add(Oauth2Grant.AuthorizationCode)
        }
        if (OAUTH2_CLIENT in metadata.authTypes) {
            add(Oauth2Grant.ClientCredentials)
        }
    }

private fun grantTypesOfAuthTypes(authTypes: List<String>): Set<Oauth2Grant> =
    buildSet {
        if (OAUTH2_CODE in authTypes) {
            add(Oauth2Grant.AuthorizationCode)
        }
        if (OAUTH2_CLIENT in authTypes) {
            add(Oauth2Grant.ClientCredentials)
        }
    }

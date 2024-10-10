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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.ValidatedAuthType
import eu.europa.ec.eudi.rqes.internal.ValidatedRSSPMetadata
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

internal object RSSPMetadataJsonParser {
    fun parseMetaData(json: String): ValidatedRSSPMetadata {
        val credentialIssuerMetadataObject =
            try {
                JsonSupport.decodeFromString<RSSPMetadataTO>(json)
            } catch (t: Throwable) {
                throw RSSPMetadataError.NonParseableRSSPMetadata(t)
            }
        return credentialIssuerMetadataObject.toDomain()
    }
}

@Serializable
private data class RSSPMetadataTO(
    @SerialName("specs") @Required val specs: String,
    @SerialName("name") @Required val name: String,
    @SerialName("logo") @Required val logo: String,
    @SerialName("region") @Required val region: String,
    @SerialName("lang") @Required val lang: String,
    @SerialName("description") @Required val description: String,
    @SerialName("authType") @Required val authTypes: List<String>,
    @SerialName("oauth2") val oauth2: String? = null,
    @SerialName("oauth2Issuer") val oauth2Issuer: String? = null,
    @SerialName("asynchronousOperationMode") val asynchronousOperationMode: Boolean? = false,
    @SerialName("methods") @Required val methods: List<String>,
    @SerialName("validationInfo") val validationInfo: Boolean? = false,
    @SerialName("signAlgorithms") @Required val signAlgorithms: SignAlgorithms,
    @SerialName("signature_formats") @Required val signatureFormats: SignatureFormats,
    @SerialName("conformance_levels") @Required val conformanceLevels: List<String>,
) {
    fun toDomain(): ValidatedRSSPMetadata {
        val grants = buildSet {
            if ("oauth2code" in authTypes) {
                add(Oauth2Grant.AuthorizationCode)
            }
            if ("oauth2client" in authTypes) {
                add(Oauth2Grant.ClientCredentials)
            }
        }

        val authTypesSupported =
            buildSet {
                authTypes.forEach() {
                    when (it) {
                        "external" -> add(ValidatedAuthType.External)
                        "tls" -> add(ValidatedAuthType.TLS)
                        "basic" -> add(ValidatedAuthType.Basic)
                        "digest" -> add(ValidatedAuthType.Digest)
                        else -> {}
                    }
                }

                if (grants.isNotEmpty()) {
                    add(
                        ValidatedAuthType.OAuth2(
                            oauth2Issuer?.let { issuer -> HttpsUrl(issuer).getOrThrow() },
                            oauth2?.let { baseUrl -> HttpsUrl(baseUrl).getOrThrow() },
                            grants,
                        ),
                    )
                }
            }
        oauth2Issuer?.let { HttpsUrl(oauth2Issuer).getOrThrow() }

        return ValidatedRSSPMetadata(
            specs = specs,
            name = name,
            logo = URI.create(logo),
            region = region,
            lang = Locale.forLanguageTag(lang),
            description = description,
            authTypes = authTypesSupported,
            asynchronousOperationMode = asynchronousOperationMode ?: false,
            methods = methods.map {
                requireNotNull(RSSPMethod.from(it)) { "Invalid RRSP method: $it" }
            },
            validationInfo = validationInfo,
        )
    }
}

@Serializable
private data class SignAlgorithms(
    @SerialName("algos") @Required val algos: List<String>,
    @SerialName("algoParams") val algoParams: List<String>? = null,
)

@Serializable
private data class SignatureFormats(
    @SerialName("formats") @Required val formats: List<String>,
    @SerialName("envelope_properties") val envelopeProperties: List<List<String>>? = null,
)

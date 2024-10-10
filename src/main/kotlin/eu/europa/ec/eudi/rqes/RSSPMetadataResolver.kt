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

import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import eu.europa.ec.eudi.rqes.internal.DefaultRSSPMetadataResolver
import java.io.Serializable
import java.net.URI
import java.util.*

/**
 * The metadata of a RSSP.
 */
data class RSSPMetadata(
    val rsspId: RSSPId,
    val specs: String,
    val name: String,
    val logo: URI,
    val region: String,
    val lang: Locale,
    val description: String,
    val authTypes: AuthTypesSupported,
    val asynchronousOperationMode: Boolean? = false,
    val methods: List<RSSPMethod>,
    val validationInfo: Boolean? = false,
)

enum class RSSPMethod {
    Info,
    AuthLogin,
    AuthRevoke,
    CredentialsList,
    CredentialsInfo,
    CredentialsAuthorize,
    CredentialsAuthorizeCheck,
    CredentialsGetChallenge,
    CredentialsSendOTP, // TODO mentioned in the spec but not described in list of methods
    CredentialsExtendTransaction,
    SignaturesSignHash,
    SignaturesSignDoc,
    SignaturesSignPolling,
    SignaturesTimestamp,
    Oauth2Authorize,
    Oauth2Token,
    Oauth2PushedAuthorize,
    Oauth2Revoke,
    ;

    companion object {
        fun from(s: String): RSSPMethod? = when (s) {
            "info" -> Info
            "auth/login" -> AuthLogin
            "auth/revoke" -> AuthRevoke
            "credentials/list" -> CredentialsList
            "credentials/info" -> CredentialsInfo
            "credentials/authorize" -> CredentialsAuthorize
            "credentials/authorizeCheck" -> CredentialsAuthorizeCheck
            "credentials/getChallenge" -> CredentialsGetChallenge
            "credentials/sendOTP" -> CredentialsSendOTP
            "credentials/extendTransaction" -> CredentialsExtendTransaction
            "signatures/signHash" -> SignaturesSignHash
            "signatures/signDoc" -> SignaturesSignDoc
            "signatures/signPolling" -> SignaturesSignPolling
            "signatures/timestamp" -> SignaturesTimestamp
            "oauth2/authorize" -> Oauth2Authorize
            "oauth2/token" -> Oauth2Token
            "oauth2/pushed_authorize" -> Oauth2PushedAuthorize
            "oauth2/revoke" -> Oauth2Revoke
            else -> null
        }
    }
}

/**
 * The authentication types supported by the RSSP.
 */
@JvmInline
value class AuthTypesSupported(val values: Set<AuthType>) {
    init {
        require(values.isNotEmpty()) { "At least one AuthType must be provided" }
    }
}

enum class Oauth2Grant {
    AuthorizationCode,
    ClientCredentials,
}

sealed interface AuthType {
    data object External : AuthType
    data object Basic : AuthType
    data object Digest : AuthType
    data object TLS : AuthType
    data class OAuth2(
        val authorizationServerMetadata: ReadOnlyAuthorizationServerMetadata,
        val grantsTypes: Set<Oauth2Grant>,
    ) : AuthType {
        init {
            require(grantsTypes.isNotEmpty()) { "At least one GrantType must be provided" }
        }
    }
}

sealed class RSSPMetadataError(cause: Throwable) : Throwable(cause), Serializable {
    class NonParseableRSSPMetadata(cause: Throwable) : RSSPMetadataError(cause)

    class UnableToFetchRSSPMetadata(cause: Throwable) : RSSPMetadataError(cause)
}

fun interface RSSPMetadataResolver {
    /**
     * Resolves the metadata of the RSSP with the given [rsspId].
     */
    suspend fun resolve(rsspId: RSSPId, lang: Locale?): Result<RSSPMetadata>

    companion object {
        /**
         * Creates a new [RSSPMetadataResolver] instance.
         */
        operator fun invoke(ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory): RSSPMetadataResolver =
            RSSPMetadataResolver { rsspId, lang ->
                ktorHttpClientFactory.invoke().use { httpClient ->
                    val resolver = DefaultRSSPMetadataResolver(httpClient)
                    resolver.resolve(rsspId, lang)
                }
            }
    }
}

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

import eu.europa.ec.eudi.rqes.AuthType.*
import eu.europa.ec.eudi.rqes.AuthType.Digest
import eu.europa.ec.eudi.rqes.internal.DefaultRSSPMetadataResolver
import java.io.Serializable
import java.net.URI
import java.util.*

data class RSSPMetadataContent<T>(
    val rsspId: RSSPId,
    val specs: String?,
    val name: String?,
    val logo: URI?,
    val region: String?,
    val lang: Locale?,
    val description: String?,
    val authTypes: Set<AuthType<T>>,
    val asynchronousOperationMode: Boolean? = false,
    val methods: List<RSSPMethod>,
    val validationInfo: Boolean = false,
) {
    init {
        require(authTypes.isNotEmpty())
        require(methods.isNotEmpty())
    }
}

internal inline fun <reified T> RSSPMetadataContent<T>.oauth2AuthType(): AuthType.OAuth2<T>? =
    authTypes.filterIsInstance<AuthType.OAuth2<T>>().firstOrNull()

/**
 * The metadata of a RSSP.
 */
typealias RSSPMetadata = RSSPMetadataContent<CSCAuthorizationServerMetadata>

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

    companion object
}

enum class Oauth2Grant {
    AuthorizationCode,
    ClientCredentials,
}

sealed interface AuthType<out T> {
    data class OAuth2<T>(val authorizationServer: T, val grantsTypes: Set<Oauth2Grant>) : AuthType<T> {
        init {
            require(grantsTypes.isNotEmpty()) { "At least one GrantType must be provided" }
        }
    }

    data object External : AuthType<Nothing>
    data object Basic : AuthType<Nothing>
    data object Digest : AuthType<Nothing>
    data object TLS : AuthType<Nothing>
}
internal inline fun <T, Y> AuthType<T>.map(f: (T) -> Y): AuthType<Y> = when (this) {
    Basic -> Basic
    Digest -> Digest
    External -> External
    is OAuth2 -> OAuth2(f(authorizationServer), grantsTypes)
    TLS -> TLS
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

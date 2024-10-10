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
import java.net.URI
import java.net.URL
import java.time.Duration
import java.time.Instant

@JvmInline
value class CredentialID(val value: String) {
    init {
        require(value.isNotBlank()) { "CredentialID must not be blank" }
    }
}

@JvmInline
value class SignatureQualifier(val value: String) {
    init {
        require(value.isNotBlank()) { "SignatureQualifier must not be blank" }
    }

    companion object {
        val EU_EIDAS_QES = SignatureQualifier("eu_eidas_qes")
        val EU_EIDAS_AES = SignatureQualifier("eu_eidas_aes")
        val EU_EIDAS_AESQC = SignatureQualifier("eu_eidas_aesqc")
        val EU_EIDAS_QESEAL = SignatureQualifier("eu_eidas_qeseal")
        val EU_EIDAS_AESEAL = SignatureQualifier("eu_eidas_aeseal")
        val EU_EIDAS_AESEALQC = SignatureQualifier("eu_eidas_aesealqc")
        val ZA_ECTA_AES = SignatureQualifier("za_ecta_aes")
        val ZA_ECTA_OES = SignatureQualifier("za_ecta_oes")
    }
}

sealed interface CredentialRef {
    data class ByCredentialID(val credentialID: CredentialID) : CredentialRef
    data class BySignatureQualifier(val signatureQualifier: SignatureQualifier) : CredentialRef
}

data class DocumentDigest(val hash: Digest, val label: String?)

@JvmInline
value class HashAlgorithmOID(val value: String) {
    init {
        require(value.isNotBlank()) { "HashAlgorithmOID must not be blank" }
    }

    companion object {
        val SHA256RSA = HashAlgorithmOID("1.2.840.113549.1.1.11")
        val SHA385RSA = HashAlgorithmOID("1.2.840.113549.1.1.12")
        val SHA512RSA = HashAlgorithmOID("1.2.840.113549.1.1.13")
    }
}

data class DocumentList(
    val documentDigests: List<DocumentDigest>,
    val hashAlgorithmOID: HashAlgorithmOID,
) {
    init {
        require(documentDigests.isNotEmpty()) { "Document list must not be empty" }
    }
}

@JvmInline
value class Digest(val value: String) {
    init {
        require(value.isNotBlank()) { "Digest must not be blank" }
    }
}

@JvmInline
value class Description(val value: String) {
    init {
        require(value.length <= 500) { "Description cannot be longer than 500 characters" }
    }
}

@JvmInline
value class RSSPId private constructor(val value: HttpsUrl) {

    override fun toString(): String =
        value.value.toString()

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [RSSPId].
         */
        operator fun invoke(value: String): Result<RSSPId> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.query.isNullOrBlank()) { "RSSPId must not have query parameters " } // TODO is it needed?
                    require(it.value.toString().endsWith("/csc/v2")) { "Base URI must end with /csc/v2" }
                    RSSPId(it)
                }
    }
}

typealias CSCAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata

/**
 * A [URI] that strictly uses the 'https' protocol.
 */
@JvmInline
value class HttpsUrl private constructor(val value: URL) {

    override fun toString(): String = value.toString()

    companion object {

        /**
         * Parses the provided [value] as a [URI] and tries creates a new [HttpsUrl].
         */
        operator fun invoke(value: String): Result<HttpsUrl> = runCatching {
            val uri = URI.create(value)
            require(uri.scheme.contentEquals("https", true)) { "URL must use https protocol" }
            HttpsUrl(uri.toURL())
        }
    }
}

/**
 * Sealed hierarchy representing a state holding the authorization request as a URL
 * to be passed to front-channel for retrieving an authorization code
 * in an oAuth2 authorization code grant type flow.
 * @param authorizationCodeURL the URL to be passed to the front-channel
 * @param pkceVerifier the PKCE verifier used for preparing the authorization request
 * @param state the state parameter used for preparing the authorization request
 */
data class AuthorizationRequestPrepared(
    val authorizationCodeURL: HttpsUrl,
    val pkceVerifier: PKCEVerifier,
    val state: String,
)

/**
 * The OAuth2 access and refresh tokens received from the authorization server.
 * @param accessToken the access token
 * @param refreshToken the refresh token, if the authorization server supports refresh tokens
 * @param timestamp the timestamp when the tokens were received
 */
data class OAuth2Tokens(
    val accessToken: AccessToken,
    val refreshToken: RefreshToken?,
    val timestamp: Instant,
) : java.io.Serializable

interface CanExpire {
    val expiresIn: Duration?

    fun isExpired(issued: Instant, at: Instant): Boolean {
        require(issued.isBefore(at) || issued == at) { "At should be after or equal to $issued" }
        val expiresIn = expiresIn
        return if (expiresIn != null) {
            val expiration = issued.plusSeconds(expiresIn.toSeconds())
            !expiration.isAfter(at)
        } else false
    }
}

data class AccessToken(
    val accessToken: String,
    override val expiresIn: Duration?,
) : CanExpire, java.io.Serializable {
    init {
        require(accessToken.isNotEmpty()) { "Access Token must not be empty" }
        if (expiresIn != null) {
            require(!expiresIn.isNegative) { "Expires in should be positive" }
        }
    }

    constructor(accessToken: String, expiresInSec: Long? = 0) :
        this(accessToken, expiresInSec?.let { Duration.ofSeconds(it) })
}

data class RefreshToken(
    val refreshToken: String,
    override val expiresIn: Duration?,
) : CanExpire, java.io.Serializable {
    init {
        require(refreshToken.isNotEmpty()) { "Refresh Token must not be empty" }
        if (expiresIn != null) {
            require(!expiresIn.isNegative) { "Expires in should be positive" }
        }
    }

    constructor(refreshToken: String, expiresInSec: Long?) :
        this(refreshToken, expiresInSec?.let { Duration.ofSeconds(it) })
}

@JvmInline
value class Scope(val value: String) {
    init {
        require(value.isNotEmpty()) { "Scope value cannot be empty" }
    }
}

@JvmInline
value class AuthorizationCode(val code: String) {
    init {
        require(code.isNotBlank()) { "Authorization code must not be blank" }
    }
}

data class PKCEVerifier(
    val codeVerifier: String,
    val codeVerifierMethod: String?,
) : java.io.Serializable {
    init {
        require(codeVerifier.isNotEmpty()) { "Code verifier must not be empty" }
    }
}

data class AuthorizationDetails(
    val credentialRef: CredentialRef,
    val numSignatures: Int,
    val documentDigests: List<DocumentDigest>,
    val hashAlgorithmOID: HashAlgorithmOID,
    val locations: List<String>? = emptyList(),
)

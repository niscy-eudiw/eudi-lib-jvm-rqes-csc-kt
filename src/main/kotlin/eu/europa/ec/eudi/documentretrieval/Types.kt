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
package eu.europa.ec.eudi.documentretrieval

import java.net.URL

data class DocumentDigest(
    val hash: String,
    val label: String,
) {
    init {
        require(hash.isNotBlank()) { "Hash must not be blank" }
        require(label.isNotBlank()) { "Label must not be blank" }
    }
}

data class DocumentLocation(
    val uri: URL,
    val method: AccessMethod,
)

sealed interface AccessMethod {

    data object Public : AccessMethod

    data object BasicAuth : AccessMethod

    data object DigestAuth : AccessMethod

    data object OAuth2 : AccessMethod

    data class OTP(val oneTimePassword: String) : AccessMethod {
        init {
            require(oneTimePassword.isNotBlank()) { "One-time password must not be blank" }
        }
    }
}

typealias Jwt = String

enum class ClientIdScheme {
    /**
     * This value represents the RFC6749 default behavior,
     * i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request
     * The Verifier's metadata is obtained using (RFC7591) or through out-of-band mechanisms.
     */
    PreRegistered,

    /**
     * When the Client Identifier Scheme is x509_san_uri, the Client Identifier
     * MUST be a URI and match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    X509_SAN_URI,

    /**
     * When the Client Identifier Scheme is x509_san_dns, the Client Identifier
     * MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    X509_SAN_DNS,

    ;

    fun value(): String = when (this) {
        PreRegistered -> OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED
        X509_SAN_URI -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI
        X509_SAN_DNS -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS
    }

    companion object {
        fun make(s: String): ClientIdScheme? = when (s) {
            OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED -> PreRegistered
            OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI -> X509_SAN_URI
            OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS -> X509_SAN_DNS
            else -> null
        }
    }
}

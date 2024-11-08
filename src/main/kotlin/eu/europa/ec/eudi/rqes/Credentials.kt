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

import java.security.cert.X509Certificate
import java.time.LocalDateTime
import javax.security.auth.x500.X500Principal

enum class Certificates {
    None, Single, Chain
}

enum class AuthorizationMode {
    Explicit, OAuth2Code
}

data class CredentialInfo(
    val credentialID: CredentialID,
    val description: CredentialDescription?,
    val signatureQualifier: SignatureQualifier?,
    val key: CredentialKey,
    val certificate: CredentialCertificate,
    val authorization: CredentialAuthorization,
    val scal: SCAL,
    val multisign: Int,
    val lang: String?,
)

enum class SCAL {
    One, Two
}

data class CredentialKey(
    val status: CredentialKeyStatus,
    val supportedAlgorithms: List<SigningAlgorithmOID>,
    val length: Int,
    val curve: String?,
)

data class CredentialCertificate(
    val status: CredentialCertificateStatus?,
    val certificates: List<X509Certificate>?,
    val issuerDN: X500Principal?,
    val serialNumber: String?,
    val subjectDN: X500Principal?,
    val validFrom: LocalDateTime?,
    val validTo: LocalDateTime?,
)

sealed interface CredentialAuthorization {
    val authorizationMode: AuthorizationMode

    data class OAuth2Code(
        override val authorizationMode: AuthorizationMode,
    ) : CredentialAuthorization

    data class Explicit(
        override val authorizationMode: AuthorizationMode,
        val expression: String?,
        val authenticationObjects: List<AuthenticationObject>?,
    ) : CredentialAuthorization
}

sealed interface AuthenticationObject {
    val type: String
    val id: String
    val label: String?
    val description: String?

    data class InBandPassword(
        override val type: String,
        override val id: String,
        override val label: String?,
        override val description: String?,
        val format: AuthenticationObjectFormat?,
        val generator: String?,
    ) : AuthenticationObject

    data class OutOfBandPassword(
        override val type: String,
        override val id: String,
        override val label: String?,
        override val description: String?,
        val format: AuthenticationObjectFormat?,
        val generator: String?,
    ) : AuthenticationObject

    data class ChallengeResponse(
        override val type: String,
        override val id: String,
        override val label: String?,
        override val description: String?,
        val format: AuthenticationObjectFormat?,
        val generator: String?,
    ) : AuthenticationObject

    data class OutOfBandChallengeResponse(
        override val type: String,
        override val id: String,
        override val label: String?,
        override val description: String?,
        val generator: String?,
    ) : AuthenticationObject
}

enum class AuthenticationObjectFormat {
    A, N
}

enum class CredentialKeyStatus {
    Enabled, Disabled
}

enum class CredentialCertificateStatus {
    Valid, Expired, Revoked, Suspended
}

@JvmInline
value class CredentialDescription(val value: String) {
    init {
        require(value.length <= 255) { "Description cannot be longer than 255 characters" }
    }
}

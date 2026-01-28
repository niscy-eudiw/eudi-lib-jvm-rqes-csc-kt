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

import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.SignatureQualifier
import java.io.Serializable
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate

/**
 * An interface that describes a service
 * that accepts an [authorization request]authorization request, validates it and resolves it (that is,
 * fetches parts of the authorization request which are provided by reference)
 *
 */
fun interface AuthorizationRequestResolver {

    /**
     * Tries to validate and request the provided [uri] into a [ResolvedRequestObject].
     */
    suspend fun resolveRequestUri(uri: String): Resolution
}

/**
 * The outcome of [validating and resolving][AuthorizationRequestResolver.resolveRequestUri]
 * an authorization request.
 */
sealed interface Resolution {
    /**
     * Represents the success of validating and resolving an authorization request
     * into a [requestObject]
     */
    data class Success(val requestObject: ResolvedRequestObject) : Resolution

    /**
     * Represents the failure of validating or resolving an authorization request
     * due to [error]
     */
    data class Invalid(val error: AuthorizationRequestError) : Resolution
}

data class ResolvedRequestObject(
    val client: Client,
    val responseMode: ResponseMode,
    val state: String?,
    val nonce: String?,
    val signatureQualifier: SignatureQualifier,
    val documentDigests: List<DocumentDigest>,
    val documentLocations: List<DocumentLocation>,
    val hashAlgorithmOID: HashAlgorithmOID,
    val clientData: String?,
) : Serializable {
    init {
        require(documentDigests.isNotEmpty()) { "documentDigests must not be empty" }
        require(documentLocations.isNotEmpty()) { "documentLocations must not be empty" }
    }
}

/**
 * Represents an OAuth2 RP that submitted an Authorization Request.
 */
sealed interface Client : Serializable {
    data class Preregistered(val clientId: String, val legalName: String) : Client
    data class X509SanDns(val clientId: String, val cert: X509Certificate) : Client
    data class X509SanUri(val clientId: URI, val cert: X509Certificate) : Client

    /**
     * The id of the client.
     */
    val id: String
        get() = when (this) {
            is Preregistered -> clientId
            is X509SanDns -> clientId
            is X509SanUri -> clientId.toString()
        }
}

/**
 * Errors that can occur while validating and resolving an authorization request
 */
sealed interface AuthorizationRequestError : Serializable

data class HttpError(val cause: Throwable) : AuthorizationRequestError

/**
 * An exception indicating an expected [error] while validating and/or resolving
 * an authorization request
 */
data class AuthorizationRequestException(val error: AuthorizationRequestError) : RuntimeException()

/**
 * Convenient method that lifts an [AuthorizationRequestError] into
 * a [AuthorizationRequestException]
 */
fun AuthorizationRequestError.asException(): AuthorizationRequestException =
    AuthorizationRequestException(this)

/**
 * Validation errors that can occur while validating an authorization request
 */
sealed interface RequestValidationError : AuthorizationRequestError {

    data class InvalidJarJwt(val cause: String) : AuthorizationRequestError

    data object InvalidRequestUriMethod : RequestValidationError {
        private fun readResolve(): Any = InvalidRequestUriMethod
    }

    data object MissingClientId : RequestValidationError {
        private fun readResolve(): Any = MissingClientId
    }

    data object InvalidClientId : RequestValidationError {
        private fun readResolve(): Any = InvalidClientId
    }

    data object UnsupportedClientIdScheme : RequestValidationError {
        private fun readResolve(): Any = UnsupportedClientIdScheme
    }

    data class InvalidClientIdScheme(val value: String) : RequestValidationError

    data object MissingRequestUri : RequestValidationError {
        private fun readResolve(): Any = MissingRequestUri
    }

    data object MissingNonce : RequestValidationError {
        private fun readResolve(): Any = MissingNonce
    }

    data object MissingResponseType : RequestValidationError {
        private fun readResolve(): Any = MissingResponseType
    }

    data object MissingResponseUri : RequestValidationError {
        private fun readResolve(): Any = MissingResponseUri
    }

    data object InvalidResponseUri : RequestValidationError {
        private fun readResolve(): Any = InvalidResponseUri
    }
    data class UnsupportedResponseType(val value: String) : RequestValidationError

    data class UnsupportedResponseMode(val value: String?) : RequestValidationError

    data object MissingSignatureQualifier : RequestValidationError {
        private fun readResolve(): Any = MissingSignatureQualifier
    }

    data object MissingHashAlgorithmOID : RequestValidationError {
        private fun readResolve(): Any = MissingHashAlgorithmOID
    }

    data object MissingDocumentDigests : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentDigests
    }

    data object MissingDocumentDigestHash : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentDigestHash
    }

    data object MissingDocumentDigestLabel : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentDigestLabel
    }

    data object MissingDocumentLocations : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentLocations
    }

    data object MissingDocumentLocationUri : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentLocationUri
    }

    data object MissingDocumentLocationMethod : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentLocationMethod
    }

    data object UnsupportedDocumentLocationMethod : RequestValidationError {
        private fun readResolve(): Any = UnsupportedDocumentLocationMethod
    }

    data object MissingDocumentLocationOTP : RequestValidationError {
        private fun readResolve(): Any = MissingDocumentLocationOTP
    }

    data object InvalidDocumentDigests : RequestValidationError {
        private fun readResolve(): Any = InvalidDocumentDigests
    }

    data object InvalidDocumentLocations : RequestValidationError {
        private fun readResolve(): Any = InvalidDocumentLocations
    }

    data class UnsupportedSignatureQualifier(val value: String) : RequestValidationError
}

sealed interface ResponseMode : Serializable {
    data class DirectPost(val responseURI: URL) : ResponseMode
}

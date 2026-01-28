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
package eu.europa.ec.eudi.documentretrieval.internal.request

import eu.europa.ec.eudi.documentretrieval.AccessMethod
import eu.europa.ec.eudi.documentretrieval.AuthorizationRequestException
import eu.europa.ec.eudi.documentretrieval.Client
import eu.europa.ec.eudi.documentretrieval.DocumentDigest
import eu.europa.ec.eudi.documentretrieval.DocumentLocation
import eu.europa.ec.eudi.documentretrieval.RequestValidationError.*
import eu.europa.ec.eudi.documentretrieval.ResolvedRequestObject
import eu.europa.ec.eudi.documentretrieval.ResponseMode
import eu.europa.ec.eudi.documentretrieval.asException
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.SignatureQualifier
import eu.europa.ec.eudi.rqes.SignatureQualifier.Companion.EU_EIDAS_QES
import eu.europa.ec.eudi.rqes.internal.ensure
import eu.europa.ec.eudi.rqes.internal.ensureNotNull
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.URI
import java.net.URL
import java.util.stream.Collectors

data class ValidatedRequestObject(
    val responseMode: ResponseMode,
    val nonce: String,
    val state: String?,
    val signatureQualifier: SignatureQualifier,
    val documentDigests: List<DocumentDigest>,
    val documentLocations: List<DocumentLocation>,
    val hashAlgorithmOID: HashAlgorithmOID,
    val clientData: String?,
)

private val jsonSupport: Json = Json { ignoreUnknownKeys = true }

/**
 * Validates that the given [request] represents a valid and supported [ValidatedRequestObject]
 *
 * @param request The request to validate
 * @return if given [request] is valid returns an appropriate [ValidatedRequestObject]. Otherwise,
 * returns a [failure][Result.Failure]. Validation rules violations are reported using [AuthorizationRequestError]
 * wrapped inside a [specific exception][AuthorizationRequestException]
 */
internal fun validateRequestObject(request: AuthenticatedRequest): ResolvedRequestObject {
    val (client, requestObject) = request
    val state = requestObject.state
    val nonce = requestObject.nonce
    val responseMode = requiredResponseMode(client, requestObject)
    val signatureQualifier = requiredSignatureQualifier(requestObject.signatureQualifier)
    val hashAlgorithmOID = requiredHashAlgorithm(requestObject.hashAlgorithmOID)
    val documentDigests = requiredDocumentDigests(requestObject.documentDigests)
    val documentLocations = requiredDocumentLocations(requestObject.documentLocations)

    return ResolvedRequestObject(
        client.toClient(),
        responseMode,
        state,
        nonce,
        signatureQualifier,
        documentDigests,
        documentLocations,
        hashAlgorithmOID,
        requestObject.clientData,
    )
}

private fun requiredDocumentDigests(
    documentDigests: JsonArray?,
): List<DocumentDigest> {
    ensureNotNull(documentDigests) { MissingDocumentDigests.asException() }
    try {
        return documentDigests.stream().map {
            jsonSupport.decodeFromJsonElement<DocumentDigestDTO>(it)
        }.map {
            ensureNotNull(it.hash) { MissingDocumentDigestHash.asException() }
            ensureNotNull(it.label) { MissingDocumentDigestLabel.asException() }
            DocumentDigest(it.hash, it.label)
        }.collect(Collectors.toList())
    } catch (_: Exception) {
        throw InvalidDocumentDigests.asException()
    }
}

private fun requiredDocumentLocations(
    documentLocations: JsonArray?,
): List<DocumentLocation> {
    ensureNotNull(documentLocations) { MissingDocumentLocations.asException() }
    try {
        return documentLocations.stream().map {
            jsonSupport.decodeFromJsonElement<DocumentLocationDTO>(it)
        }.map {
            ensureNotNull(it.uri) { MissingDocumentLocationUri.asException() }
            ensureNotNull(it.method) { MissingDocumentLocationMethod.asException() }
            ensureNotNull(it.method.type) { MissingDocumentLocationMethod.asException() }
            val method: AccessMethod = when (it.method.type) {
                "public" -> AccessMethod.Public
                "Basic_Auth" -> AccessMethod.BasicAuth
                "Digest_Auth" -> AccessMethod.DigestAuth
                "OAuth_20" -> AccessMethod.OAuth2
                "OTP" -> AccessMethod.OTP(it.method.oneTimePassword ?: throw MissingDocumentLocationOTP.asException())
                else -> throw UnsupportedDocumentLocationMethod.asException()
            }
            DocumentLocation(
                uri = it.uri.asURL { MissingDocumentLocationUri.asException() }.getOrThrow(),
                method = method,
            )
        }.collect(Collectors.toList())
    } catch (e: AuthorizationRequestException) {
        throw e
    } catch (_: Exception) {
        throw InvalidDocumentLocations.asException()
    }
}

@Serializable
data class DocumentDigestDTO(
    val hash: String?,
    val label: String?,
)

@Serializable
internal data class DocumentLocationDTO(
    @SerialName("uri") val uri: String? = null,
    @SerialName("method") val method: MethodDTO? = null,
)

@Serializable
internal data class MethodDTO(
    @SerialName("type") val type: String? = null,
    @SerialName("oneTimePassword") val oneTimePassword: String? = null,
)

private fun requiredHashAlgorithm(
    hashAlgorithmOID: String?,
): HashAlgorithmOID {
    ensureNotNull(hashAlgorithmOID) { MissingHashAlgorithmOID.asException() }
    return HashAlgorithmOID(hashAlgorithmOID)
}

private fun requiredSignatureQualifier(
    signatureQualifierStr: String?,
): SignatureQualifier {
    ensureNotNull(signatureQualifierStr) { MissingSignatureQualifier.asException() }
    return when (signatureQualifierStr) {
        EU_EIDAS_QES.value -> SignatureQualifier(signatureQualifierStr)
        else -> throw UnsupportedSignatureQualifier(signatureQualifierStr).asException()
    }
}

private fun requiredResponseMode(
    client: AuthenticatedClient,
    unvalidated: UnvalidatedRequestObject,
): ResponseMode {
    fun requiredResponseUri(): URL {
        val uri = unvalidated.responseUri
        ensureNotNull(uri) { MissingResponseUri.asException() }
        return uri.asURL { InvalidResponseUri.asException() }.getOrThrow()
    }

    val responseMode = when (unvalidated.responseMode) {
        "direct_post" -> requiredResponseUri().let { ResponseMode.DirectPost(it) }
        else -> throw UnsupportedResponseMode(unvalidated.responseMode).asException()
    }

    val uri = responseMode.uri()
    when (client) {
        is AuthenticatedClient.Preregistered -> Unit
        is AuthenticatedClient.X509SanDns -> ensure(client.clientId == uri.host) {
            UnsupportedResponseMode("$responseMode host doesn't match ${client.clientId}").asException()
        }

        is AuthenticatedClient.X509SanUri -> ensure(client.clientId == uri) {
            UnsupportedResponseMode("$responseMode doesn't match ${client.clientId}").asException()
        }
    }
    return responseMode
}

private fun ResponseMode.uri(): URI = when (this) {
    is ResponseMode.DirectPost -> responseURI.toURI()
}

private fun AuthenticatedClient.toClient(): Client =
    when (this) {
        is AuthenticatedClient.Preregistered -> Client.Preregistered(
            preregisteredClient.clientId,
            preregisteredClient.legalName,
        )

        is AuthenticatedClient.X509SanDns -> Client.X509SanDns(clientId, chain[0])
        is AuthenticatedClient.X509SanUri -> Client.X509SanUri(clientId, chain[0])
    }

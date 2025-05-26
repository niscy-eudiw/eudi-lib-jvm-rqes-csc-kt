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
import eu.europa.ec.eudi.rqes.internal.http.AuthenticationObjectTO.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialAuthTO.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialKeyCertificateTO.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialKeyTO.Companion.toDomain
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.ByteArrayInputStream
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import javax.security.auth.x500.X500Principal

@Serializable
private data class CredentialsListRequestTO(
    @SerialName("credentialInfo") val credentialInfo: Boolean? = false,
    @SerialName("certificates") val certificates: String? = Certificates.Single.toString(),
    @SerialName("certInfo") val certInfo: Boolean? = false,
    @SerialName("authInfo") val authInfo: Boolean? = false,
    @SerialName("onlyValid") val onlyValid: Boolean? = false,
    @SerialName("lang") val lang: String? = null,
    @SerialName("clientData") val clientData: String? = null,
) {
    companion object {
        fun from(request: CredentialsListRequest): CredentialsListRequestTO = CredentialsListRequestTO(
            credentialInfo = request.credentialInfo,
            certificates = request.certificates?.toString()?.lowercase(),
            certInfo = request.certInfo,
            authInfo = request.authInfo,
            onlyValid = request.onlyValid,
            lang = request.lang,
            clientData = request.clientData,
        )
    }
}

internal sealed interface CredentialsListTO {
    @Serializable
    data class Success(
        @SerialName("credentialIDs") @Required val credentialIds: List<String>,
        @SerialName("credentialInfos") val credentialInfos: List<ListCredentialInfoTO>? = null,
        @SerialName("onlyValid") val onlyValid: Boolean? = null,
    ) : CredentialsListTO

    @Serializable
    data class Failure(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialsListTO
}

@Serializable
internal class ListCredentialInfoTO(
    @SerialName("credentialID") @Required val credentialId: String,
    @SerialName("description") val description: String? = null,
    @SerialName("signatureQualifier") val signatureQualifier: String? = null,
    @SerialName("key") val key: CredentialKeyTO,
    @SerialName("cert") val certificate: CredentialKeyCertificateTO,
    @SerialName("auth") @Required val auth: CredentialAuthTO,
    @SerialName("SCAL") val scal: String? = "1",
    @SerialName("multisign") @Required val multisign: Int,
    @SerialName("lang") val lang: String? = null,
) {
    companion object {
        fun ListCredentialInfoTO.toDomain(): CredentialInfo = CredentialInfo(
            credentialID = CredentialID(credentialId),
            description = description?.let { CredentialDescription(it) },
            signatureQualifier = signatureQualifier?.let { SignatureQualifier(it) },
            key = key.toDomain(),
            certificate = certificate.toDomain(),
            authorization = auth.toDomain(),
            scal = if (scal == "1") SCAL.One else SCAL.Two,
            multisign = multisign,
            lang = null,
        )
    }
}

@Serializable
internal class CredentialKeyTO(
    @SerialName("status") @Required val status: String,
    @SerialName("algo") @Required val algo: List<String>,
    @SerialName("len") @Required val length: Int,
    @SerialName("curve") val curve: String? = null,
) {
    companion object {
        fun CredentialKeyTO.toDomain(): CredentialKey = CredentialKey(
            status = toCredentialKeyStatus(status),
            supportedAlgorithms = algo.map { SigningAlgorithmOID(it) },
            length = length,
            curve = curve,
        )
    }
}

private fun toCredentialKeyStatus(value: String) =
    when (value) {
        "enabled" -> CredentialKeyStatus.Enabled
        "disabled" -> CredentialKeyStatus.Disabled
        else -> throw IllegalArgumentException("Unknown credential key status: $value")
    }

private fun toCertificateStatus(value: String) =
    when (value) {
        "valid" -> CredentialCertificateStatus.Valid
        "expired" -> CredentialCertificateStatus.Expired
        "revoked" -> CredentialCertificateStatus.Revoked
        "suspended" -> CredentialCertificateStatus.Suspended
        else -> throw IllegalArgumentException("Unknown certificate status: $value")
    }

private fun toAuthorizationMode(value: String) =
    when (value) {
        "explicit" -> AuthorizationMode.Explicit
        "oauth2code" -> AuthorizationMode.OAuth2Code
        else -> throw IllegalArgumentException("Unknown authorization mode: $value")
    }

@Serializable
internal class CredentialKeyCertificateTO(
    @SerialName("status") val status: String? = null,
    @SerialName("certificates") val certificates: List<String>? = null,
    @SerialName("issuerDN") val issuerDN: String? = null,
    @SerialName("serialNumber") val serialNumber: String? = null,
    @SerialName("subjectDN") val subjectDN: String? = null,
    @SerialName("validFrom") val validFrom: String? = null,
    @SerialName("validTo") val validTo: String? = null,
) {
    companion object {
        fun CredentialKeyCertificateTO.toDomain(): CredentialCertificate = CredentialCertificate(
            status = status?.let { toCertificateStatus(it) },
            certificates = certificates?.map {
                val certificateBytes: ByteArray = Base64.getDecoder().decode(it)
                val inputStream = ByteArrayInputStream(certificateBytes)
                val x509CertificateFactory = CertificateFactory.getInstance("X.509")
                x509CertificateFactory.generateCertificate(inputStream) as X509Certificate
            },
            rawCertificates = certificates ?: emptyList(),
            issuerDN = X500Principal(issuerDN),
            serialNumber = serialNumber,
            subjectDN = X500Principal(subjectDN),
            validFrom = validFrom?.let { LocalDateTime.parse(it, DateTimeFormatter.ofPattern("yyyyMMddHHmmssX")) },
            validTo = validTo?.let { LocalDateTime.parse(it, DateTimeFormatter.ofPattern("yyyyMMddHHmmssX")) },
        )
    }
}

@Serializable
internal class CredentialAuthTO(
    @SerialName("mode") @Required val mode: String,
    @SerialName("expression") val expression: String? = "AND",
    @SerialName("objects") @Required val objects: List<AuthenticationObjectTO>?,
) {
    companion object {
        fun CredentialAuthTO.toDomain(): CredentialAuthorization = when (mode) {
            "oauth2Code" -> CredentialAuthorization.OAuth2Code(
                authorizationMode = toAuthorizationMode(mode),
            )

            else -> CredentialAuthorization.Explicit(
                authorizationMode = toAuthorizationMode(mode),
                expression = expression,
                authenticationObjects = objects?.map { it.toDomain() },
            )
        }
    }
}

@Serializable
internal class AuthenticationObjectTO(
    @SerialName("type") @Required val type: String,
    @SerialName("id") @Required val id: String,
    @SerialName("label") val label: String? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("format") val format: String? = null,
    @SerialName("generator") val generator: String? = null,
) {
    companion object {
        fun AuthenticationObjectTO.toDomain(): AuthenticationObject = when (type) {
            "Password" -> AuthenticationObject.InBandPassword(
                type = type,
                id = id,
                label = label,
                description = description,
                format = format?.let { AuthenticationObjectFormat.valueOf(it) },
                generator = generator,
            )

            "PasswordOOB" -> AuthenticationObject.OutOfBandPassword(
                type = type,
                id = id,
                label = label,
                description = description,
                format = format?.let { AuthenticationObjectFormat.valueOf(it) },
                generator = generator,
            )

            "ChallengeResponse" -> AuthenticationObject.ChallengeResponse(
                type = type,
                id = id,
                label = label,
                description = description,
                format = format?.let { AuthenticationObjectFormat.valueOf(it) },
                generator = generator,
            )

            "ChallengeResponseOOB" -> AuthenticationObject.OutOfBandChallengeResponse(
                type = type,
                id = id,
                label = label,
                description = description,
                generator = generator,
            )

            else -> throw IllegalArgumentException("Unknown authentication object type: $type")
        }
    }
}

internal class CredentialsListEndpointClient(
    private val rsspBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    suspend fun listCredentials(request: CredentialsListRequest, accessToken: AccessToken): Result<CredentialsListTO> =
        runCatching {
            ktorHttpClientFactory().use { client ->
                val response = client.post("$rsspBaseURL/credentials/list") {
                    bearerAuth(accessToken.accessToken)
                    contentType(ContentType.Application.Json)
                    setBody(CredentialsListRequestTO.from(request))
                }
                if (response.status.isSuccess()) {
                    response.body<CredentialsListTO.Success>()
                } else {
                    response.body<CredentialsListTO.Failure>()
                }
            }
        }
}

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
import eu.europa.ec.eudi.rqes.internal.http.CredentialAuthTO.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialKeyCertificateTO.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialKeyTO.Companion.toDomain
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL

@Serializable
private data class CredentialsInfoRequestTO(
    @SerialName("credentialID") val credentialID: String,
    @SerialName("certificates") val certificates: String? = Certificates.Single.toString(),
    @SerialName("certInfo") val certInfo: Boolean? = false,
    @SerialName("authInfo") val authInfo: Boolean? = false,
    @SerialName("lang") val lang: String? = null,
    @SerialName("clientData") val clientData: String? = null,
) {
    companion object {
        fun from(request: CredentialsInfoRequest): CredentialsInfoRequestTO = CredentialsInfoRequestTO(
            credentialID = request.credentialID.value,
            certificates = request.certificates?.toString()?.lowercase(),
            certInfo = request.certInfo,
            authInfo = request.authInfo,
            lang = request.lang,
            clientData = request.clientData,
        )
    }
}

internal sealed interface CredentialInfoTO {

    @Serializable
    data class Success(
        @SerialName("description") val description: String? = null,
        @SerialName("signatureQualifier") val signatureQualifier: String? = null,
        @SerialName("key") val key: CredentialKeyTO,
        @SerialName("cert") val certificate: CredentialKeyCertificateTO,
        @SerialName("auth") @Required val auth: CredentialAuthTO,
        @SerialName("SCAL") val scal: String? = "1",
        @SerialName("multisign") @Required val multisign: Int,
        @SerialName("lang") val lang: String? = null,
    ) : CredentialInfoTO {
        companion object {
            fun Success.toDomain(credentialID: CredentialID): CredentialInfo = CredentialInfo(
                credentialID = credentialID,
                description = description?.let { CredentialDescription(it) },
                signatureQualifier = signatureQualifier?.let { SignatureQualifier(it) },
                key = key.toDomain(),
                certificate = certificate.toDomain(),
                authorization = auth.toDomain(),
                scal = if (scal == "2") SCAL.Two else SCAL.One,
                multisign = multisign,
                lang = null,
            )
        }
    }

    @Serializable
    data class Failure(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialInfoTO
}

internal class CredentialsInfoEndpointClient(
    private val rsspBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    suspend fun credentialInfo(request: CredentialsInfoRequest, accessToken: AccessToken): Result<CredentialInfoTO> =
        runCatching {
            ktorHttpClientFactory().use { client ->
                val response = client.post("$rsspBaseURL/credentials/info") {
                    bearerAuth(accessToken.accessToken)
                    contentType(ContentType.Application.Json)
                    setBody(CredentialsInfoRequestTO.from(request))
                }
                if (response.status.isSuccess()) {
                    response.body<CredentialInfoTO.Success>()
                } else {
                    response.body<CredentialInfoTO.Failure>()
                }
            }
        }
}

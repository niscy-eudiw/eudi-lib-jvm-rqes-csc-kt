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
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.FileInputStream
import java.net.URL
import java.time.Instant

internal data class ObtainSignedDocResponse(
    val documentWithSignature: List<String>,
    val signatures: List<String>,
)

@Serializable
private data class ObtainSignedDocRequestTO(
    @SerialName("documents") val documents: List<DocumentToSignTO>,
    @SerialName("endEntityCertificate") val endEntityCertificate: String,
    @SerialName("certificateChain") val certificateChain: List<String>? = null,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String,
    @SerialName("date") val date: Long,
    @SerialName("signatures") val signatures: List<String>,
)

@Serializable
internal sealed interface ObtainSignedDocResponseTO {

    @Serializable
    data class Success(
        @SerialName("documentWithSignature") val documentWithSignature: List<String>,
        @SerialName("signatureObject") val signatures: List<String>,
    ) : ObtainSignedDocResponseTO

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : ObtainSignedDocResponseTO

    fun getOrFail(): ObtainSignedDocResponse =
        when (this) {
            is Success -> ObtainSignedDocResponse(documentWithSignature, signatures)
            is Failure -> throw RuntimeException("Error: $error, $errorDescription")
        }
}

internal class SCAObtainSignedDocEndpointClient(
    private val scaBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {
    suspend fun obtainSignedDoc(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
        signatures: List<Signature>,
        signatureTimestamp: Instant,
    ): ObtainSignedDocResponse =
        ktorHttpClientFactory().use { client ->

            requireNotNull(credentialCertificate.certificates) {
                "Certificate is required for hash calculation"
            }

            val response = client.post("$scaBaseURL/signatures/obtain_signed_doc") {
                contentType(ContentType.Application.Json)
                setBody(
                    ObtainSignedDocRequestTO(
                        documents = documents.map {
                            DocumentToSignTO(
                                document = FileInputStream(it.file.content).toBase64(),
                                signatureFormat = it.signatureFormat,
                                conformanceLevel = SCAConformanceLevel.fromDomain(it.conformanceLevel),
                                signedEnvelopeProperty = it.signedEnvelopeProperty,
                                asicContainer = SCAASICContainer.fromDomain(it.asicContainer),
                            )
                        },
                        endEntityCertificate = credentialCertificate.certificates.first().toBase64(),
                        certificateChain = if (credentialCertificate.certificates.size > 1) {
                            credentialCertificate.certificates.drop(1).map { it.toBase64() }
                        } else null,
                        hashAlgorithmOID = hashAlgorithmOID.value,
                        date = signatureTimestamp.toEpochMilli(),
                        signatures = signatures.map { it.value },
                    ),
                )
            }
            if (response.status.isSuccess()) {
                response.body<ObtainSignedDocResponseTO.Success>()
            } else {
                response.body<ObtainSignedDocResponseTO.Failure>()
            }
        }.getOrFail()
}

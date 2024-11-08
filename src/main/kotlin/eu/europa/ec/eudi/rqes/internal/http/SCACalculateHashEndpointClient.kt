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
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.InputStream
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.*

internal data class CalculateHashResponse(
    val hashes: List<String>,
    val signatureDate: Instant,
)

@Serializable
private data class CalculateHashRequestTO(
    @SerialName("documents") val documents: List<DocumentToSignTO>,
    @SerialName("endEntityCertificate") val endEntityCertificate: String,
    @SerialName("certificateChain") val certificateChain: List<String>? = null,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String,
)

@Serializable
internal data class DocumentToSignTO(
    @SerialName("document") @Required val document: String,
    @SerialName("signature_format") @Required val signatureFormat: SignatureFormat,
    @SerialName("conformance_level") @Required val conformanceLevel: SCAConformanceLevel,
    @SerialName("signed_envelope_property") @Required val signedEnvelopeProperty: SignedEnvelopeProperty,
    @SerialName("container") @Required val asicContainer: SCAASICContainer,
)

@Serializable
internal enum class SCAConformanceLevel() {

    @SerialName("Ades-B-B")
    ADES_B_B,

    @SerialName("Ades-B-T")
    ADES_B_T,

    @SerialName("Ades-B-LT")
    ADES_B_LT,

    @SerialName("Ades-B-LTA")
    ADES_B_LTA,

    @SerialName("Ades-B")
    ADES_B,

    @SerialName("Ades-T")
    ADES_T,

    @SerialName("Ades-LT")
    ADES_LT,

    @SerialName("Ades-LTA")
    ADES_LTA,

    ;

    companion object {
        fun fromDomain(value: ConformanceLevel): SCAConformanceLevel =
            when (value) {
                ConformanceLevel.ADES_B_B -> ADES_B_B
                ConformanceLevel.ADES_B_T -> ADES_B_T
                ConformanceLevel.ADES_B_LT -> ADES_B_LT
                ConformanceLevel.ADES_B_LTA -> ADES_B_LTA
                ConformanceLevel.ADES_B -> ADES_B
                ConformanceLevel.ADES_T -> ADES_T
                ConformanceLevel.ADES_LT -> ADES_LT
                ConformanceLevel.ADES_LTA -> ADES_LTA
            }
    }
}

internal enum class SCAASICContainer() {

    @SerialName("No")
    NONE,

    @SerialName("ASiC-E")
    ASIC_E,

    @SerialName("ASiC-S")
    ASIC_S,

    ;

    companion object {
        fun fromDomain(value: ASICContainer): SCAASICContainer =
            when (value) {
                ASICContainer.NONE -> NONE
                ASICContainer.ASIC_E -> ASIC_E
                ASICContainer.ASIC_S -> ASIC_S
            }
    }
}

internal sealed interface CalculateHashResponseTO {

    @Serializable
    data class Success(
        @SerialName("hashes") val hashes: List<String>,
        @SerialName("signature_date") val signatureDate: Long,
    ) : CalculateHashResponseTO

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : CalculateHashResponseTO

    fun getOrFail(): CalculateHashResponse =
        when (this) {
            is Success -> CalculateHashResponse(
                hashes, // .map { URLDecoder.decode(it, Charsets.UTF_8) },
                Instant.ofEpochMilli(signatureDate),
            )

            is Failure -> throw RuntimeException("Error: $error, $errorDescription")
        }
}

internal fun X509Certificate.toBase64(): String {
    val encoded = this.encoded // Get the encoded form of the certificate
    return Base64.getEncoder().encodeToString(encoded) // Encode the byte array to a Base64 string
}

internal class SCACalculateHashEndpointClient(
    private val scaBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {
    suspend fun calculateHash(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): CalculateHashResponse =
        ktorHttpClientFactory().use { client ->

            requireNotNull(credentialCertificate.certificates) {
                "Certificate is required for hash calculation"
            }

            val response = client.post("$scaBaseURL/signatures/calculate_hash") {
                contentType(ContentType.Application.Json)
                setBody(
                    CalculateHashRequestTO(
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
                        certificateChain = if (credentialCertificate.certificates.size > 1) credentialCertificate.certificates.drop(
                            1,
                        ).map { it.toBase64() } else null,
                        hashAlgorithmOID = hashAlgorithmOID.value,
                    ),
                )
            }
            if (response.status.isSuccess()) {
                response.body<CalculateHashResponseTO.Success>()
            } else {
                response.body<CalculateHashResponseTO.Failure>()
            }
        }.getOrFail()
}

internal fun InputStream.toBase64(): String {
    val buffer = ByteArray(8192) // 8KB buffer
    val outputStream = ByteArrayOutputStream()
    Base64.getEncoder().wrap(outputStream).use { it ->
        var bytesRead: Int
        while (this.read(buffer).also { bytesRead = it } != -1) {
            it.write(buffer, 0, bytesRead)
        }
    }
    return outputStream.toString("UTF-8")
}

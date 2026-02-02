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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL

@Serializable
internal data class SignHashRequestTO(
    @SerialName("credentialID") val credentialID: String,
    @SerialName("hashes") val hashes: List<String>,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String,
    @SerialName("signAlgo") val signAlgorithmOID: String,
    @SerialName("signAlgoParams") val signAlgorithmParams: String?,
    @SerialName("operationMode") val operationMode: String = "S",
)

@Serializable
internal sealed interface SignHashResponseTO {

    @Serializable
    data class Success(
        @SerialName("signatures") val signatures: List<String>,
    ) : SignHashResponseTO

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : SignHashResponseTO

    fun getOrFail(): SignaturesList =
        when (this) {
            is Success -> SignaturesList(signatures.map { Signature(it) })
            is Failure -> throw RuntimeException("Error: $error, $errorDescription")
        }
}

internal class SignHashEndpointClient(
    private val cscBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    suspend fun signHashes(
        credentialID: CredentialID,
        hashes: List<String>,
        hashAlgorithmOID: HashAlgorithmOID,
        signAlgorithmOID: SigningAlgorithmOID,
        signingAlgorithmParams: String?,
        token: AccessToken,
    ): SignaturesList =
        ktorHttpClientFactory().use { client ->
            val response = client.post("$cscBaseURL/signatures/signHash") {
                header("Authorization", "Bearer ${token.accessToken}")
                contentType(ContentType.Application.Json)
                setBody(
                    SignHashRequestTO(
                        credentialID.value,
                        hashes,
                        hashAlgorithmOID.value,
                        signAlgorithmOID.value,
                        signingAlgorithmParams,
                    ),
                )
            }

            if (response.status.isSuccess()) {
                response.body<SignHashResponseTO.Success>()
            } else {
                response.body<SignHashResponseTO.Failure>()
            }
        }.getOrFail()
}

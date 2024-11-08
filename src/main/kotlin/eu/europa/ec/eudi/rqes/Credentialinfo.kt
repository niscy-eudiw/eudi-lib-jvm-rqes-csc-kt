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

import eu.europa.ec.eudi.rqes.internal.http.CredentialInfoTO
import eu.europa.ec.eudi.rqes.internal.http.CredentialInfoTO.Success.Companion.toDomain
import eu.europa.ec.eudi.rqes.internal.http.CredentialsInfoEndpointClient

data class CredentialsInfoRequest(
    val credentialID: CredentialID,
    val certificates: Certificates? = Certificates.Chain,
    val certInfo: Boolean? = true,
    val authInfo: Boolean? = true,
    val lang: String? = null,
    val clientData: String? = null,
)

fun interface GetCredentialInfo {

    suspend fun ServiceAccessAuthorized.credentialInfo(
        request: CredentialsInfoRequest,
    ): Result<CredentialInfo>

    companion object {
        internal operator fun invoke(credentialsInfoEndpointClient: CredentialsInfoEndpointClient): GetCredentialInfo =
            GetCredentialInfo { request ->
                runCatching {
                    val credentialsInfo = credentialsInfoEndpointClient.credentialInfo(
                        request,
                        tokens.accessToken,
                    ).getOrThrow()

                    when (credentialsInfo) {
                        is CredentialInfoTO.Success -> credentialsInfo.toDomain(request.credentialID)
                        else -> throw IllegalStateException("Unexpected response: $credentialsInfo")
                    }
                }
            }
    }
}

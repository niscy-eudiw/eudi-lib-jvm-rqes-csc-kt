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
package eu.europa.ec.eudi.documentretrieval.internal.response

import eu.europa.ec.eudi.documentretrieval.AuthorizationRequestError
import eu.europa.ec.eudi.documentretrieval.HttpError
import eu.europa.ec.eudi.documentretrieval.RequestValidationError.*

internal enum class AuthorizationRequestErrorCode(val code: String) {

    /**
     * OpenId4VP Error Codes
     */
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),

    /**
     * SIOPv2 Error Codes
     */
    USER_CANCELLED("user_cancelled"),
    ;

    companion object {

        /**
         * Maps an [error] into a [AuthorizationRequestErrorCode]
         */
        fun fromError(error: AuthorizationRequestError): AuthorizationRequestErrorCode {
            return when (error) {
                InvalidClientId, UnsupportedClientIdScheme -> INVALID_CLIENT

                is InvalidJarJwt,
                is InvalidClientIdScheme,
                InvalidResponseUri,
                MissingClientId,
                MissingNonce,
                MissingResponseType,
                MissingResponseUri,
                is UnsupportedResponseMode,
                is UnsupportedResponseType,
                is HttpError,
                InvalidRequestUriMethod,
                InvalidDocumentDigests,
                InvalidDocumentLocations,
                MissingDocumentDigests,
                MissingDocumentLocations,
                MissingHashAlgorithmOID,
                MissingRequestUri,
                MissingSignatureQualifier,
                is UnsupportedSignatureQualifier,
                MissingDocumentDigestHash,
                MissingDocumentDigestLabel,
                MissingDocumentLocationMethod,
                MissingDocumentLocationOTP,
                MissingDocumentLocationUri,
                UnsupportedDocumentLocationMethod,
                -> INVALID_REQUEST
            }
        }
    }
}

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
package eu.europa.ec.eudi.rqes

interface SignHash {

    /**
     * Signs the hash of the given document digest list using the given signing algorithm OID.
     * @param documentDigestList the document digests to sign
     * @param signingAlgorithmOID the signing algorithm OID to use
     * @return the list of signatures
     */
    suspend fun CredentialAuthorized.SCAL1.signHash(
        documentDigestList: DocumentDigestList,
        signingAlgorithmOID: SigningAlgorithmOID,
    ): Result<SignaturesList>

    /**
     * Signs the hash of the given document digest list using the given signing algorithm OID.
     * @param signingAlgorithmOID the signing algorithm OID to use
     * @return the list of signatures
     */
    suspend fun CredentialAuthorized.SCAL2.signHash(signingAlgorithmOID: SigningAlgorithmOID): Result<SignaturesList>
}

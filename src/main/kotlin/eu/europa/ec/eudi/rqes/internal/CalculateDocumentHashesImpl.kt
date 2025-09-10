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
package eu.europa.ec.eudi.rqes.internal

import eu.europa.ec.eudi.podofomanager.PodofoManager
import eu.europa.ec.eudi.rqes.*

internal class CalculateDocumentHashesImpl() : CalculateDocumentHashes {
    companion object {
        private var podofoManager: PodofoManager? = null
        private var tsaUrl: String? = null

        internal fun initialize(podofoManager: PodofoManager, tsaUrl: String?) {
            this.podofoManager = podofoManager
            this.tsaUrl = tsaUrl
        }
    }

    override suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): DocumentDigestList {
        val pdfManager = podofoManager ?: throw IllegalStateException("PodofoManager is not initialized")
        val tsaUrl = tsaUrl ?: ""
        return pdfManager.calculateDocumentHashes(documents, credentialCertificate, hashAlgorithmOID, tsaUrl)
    }
}

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
import kotlinx.coroutines.runBlocking

internal class CreateSignedDocumentsImpl() : CreateSignedDocuments {
    companion object {
        private var podofoManager: PodofoManager? = null
        private var tsaUrl: String? = null
        private var includeRevocationInfo: Boolean = false

        internal fun initialize(podofoManager: PodofoManager, cscClientConfig: CSCClientConfig) {
            this.podofoManager = podofoManager
            this.tsaUrl = cscClientConfig.tsaurl
            this.includeRevocationInfo = cscClientConfig.includeRevocationInfo
        }
    }

    override suspend fun createSignedDocuments(
        signatures: List<Signature>,
    ) = runBlocking {
        val pdfManager = podofoManager ?: throw IllegalStateException("PodofoManager is not initialized")
        val tsaUrl = tsaUrl ?: ""
        pdfManager.createSignedDocuments(signatures.map { it.value }, tsaUrl, includeRevocationInfo)
    }
}

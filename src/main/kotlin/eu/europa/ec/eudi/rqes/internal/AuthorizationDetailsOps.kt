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
package eu.europa.ec.eudi.rqes.internal

import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import com.nimbusds.oauth2.sdk.rar.AuthorizationType
import eu.europa.ec.eudi.rqes.CredentialAuthorizationSubject
import eu.europa.ec.eudi.rqes.CredentialRef
import eu.europa.ec.eudi.rqes.Scope
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject

internal fun CredentialAuthorizationSubject.toNimbusAuthDetail(): AuthorizationDetail {
    val hashesArray = documentDigestList?.let {
        val docDigests = JSONArray()
        it.documentDigests.forEach() { documentDigest ->
            docDigests.add(
                JSONObject().apply {
                    put("hash", documentDigest.hash.value)
                    put("label", documentDigest.label)
                },
            )
        }
        docDigests
    }

    return AuthorizationDetail.Builder(AuthorizationType(Scope.Credential.value)).apply {
        when (credentialRef) {
            is CredentialRef.ByCredentialID -> field("credentialID", credentialRef.credentialID.value)
            is CredentialRef.BySignatureQualifier -> field("signatureQualifier", credentialRef.signatureQualifier.value)
        }
        documentDigestList?.let {
            field("documentDigests", hashesArray)
            field("hashAlgorithmOID", it.hashAlgorithmOID.value)
        }
    }.build()
}

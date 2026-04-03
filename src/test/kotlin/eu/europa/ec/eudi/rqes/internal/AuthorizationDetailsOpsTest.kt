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

import eu.europa.ec.eudi.rqes.*
import net.minidev.json.JSONArray
import net.minidev.json.JSONObject
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class AuthorizationDetailsOpsTest {

    @Test
    fun `toNimbusAuthDetail with ByCredentialID and no document digests`() {
        val credentialID = CredentialID("test-credential-id")
        val subject = CredentialAuthorizationSubject(
            credentialRef = CredentialRef.ByCredentialID(credentialID),
            documentDigestList = null,
            numSignatures = 1,
        )

        val authDetail = subject.toNimbusAuthDetail()

        assertEquals("https://cloudsignatureconsortium.org/2025/credential", authDetail.toJSONObject().get("type"))
        assertEquals(1, authDetail.toJSONObject().get("numSignatures"))
        assertEquals("test-credential-id", authDetail.toJSONObject().get("credentialID"))
        assertNull(authDetail.toJSONObject()["signatureQualifier"])
        assertNull(authDetail.toJSONObject()["documentDigests"])
        assertNull(authDetail.toJSONObject()["hashAlgorithmOID"])
    }

    @Test
    fun `toNimbusAuthDetail with BySignatureQualifier and no document digests`() {
        val signatureQualifier = SignatureQualifier.EU_EIDAS_QES
        val subject = CredentialAuthorizationSubject(
            credentialRef = CredentialRef.BySignatureQualifier(signatureQualifier),
            documentDigestList = null,
            numSignatures = 5,
        )

        val authDetail = subject.toNimbusAuthDetail()

        assertEquals("https://cloudsignatureconsortium.org/2025/credential", authDetail.toJSONObject().get("type"))
        assertEquals(5, authDetail.toJSONObject()["numSignatures"])
        assertEquals(SignatureQualifier.EU_EIDAS_QES.value, authDetail.toJSONObject()["signatureQualifier"])
        assertNull(authDetail.toJSONObject()["credentialID"])
    }

    @Test
    fun `toNimbusAuthDetail with document digests`() {
        val credentialID = CredentialID("test-id")
        val digest1 = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")
        val digest2 = Digest.Base64Digest("vTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=")

        val documentDigestList = DocumentDigestList(
            documentDigests = listOf(
                DocumentDigest(hash = digest1, label = "doc1", hashType = HashType.DTBSR),
                DocumentDigest(hash = digest2, label = "doc2", hashType = HashType.SDR),
            ),
            hashAlgorithmOID = HashAlgorithmOID.SHA_256,
            hashCalculationTime = Instant.now(),
        )

        val subject = CredentialAuthorizationSubject(
            credentialRef = CredentialRef.ByCredentialID(credentialID),
            documentDigestList = documentDigestList,
            numSignatures = 2,
        )

        val authDetail = subject.toNimbusAuthDetail()

        assertEquals("https://cloudsignatureconsortium.org/2025/credential", authDetail.toJSONObject().get("type"))
        assertEquals(2, authDetail.toJSONObject().get("numSignatures"))
        assertEquals("test-id", authDetail.toJSONObject().get("credentialID"))
        assertEquals(HashAlgorithmOID.SHA_256.value, authDetail.toJSONObject().get("hashAlgorithmOID"))

        val digests = assertIs<JSONArray>(authDetail.toJSONObject().get("documentDigests"))
        assertEquals(2, digests.size)

        val d1 = assertIs<JSONObject>(digests[0])
        assertEquals(digest1.asBase64(), d1.get("hash"))
        assertEquals("doc1", d1.get("label"))
        assertEquals("DTBSR", d1.get("hashType"))

        val d2 = assertIs<JSONObject>(digests[1])
        assertEquals(digest2.asBase64(), d2.get("hash"))
        assertEquals("doc2", d2.get("label"))
        assertEquals("SDR", d2.get("hashType"))
    }
}

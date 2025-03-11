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
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.rqes.DefaultHttpClientFactory
import eu.europa.ec.eudi.rqes.Signature
import eu.europa.ec.eudi.rqes.SignaturesList
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.util.*

fun main() {
    runBlocking {
        val config = DocumentRetrievalConfig(
            jarConfiguration = JarConfiguration(
                supportedAlgorithms = listOf(JWSAlgorithm.ES256),
            ),
            clock = Clock.systemDefaultZone(),
            jarClockSkew = Duration.ofSeconds(15L),
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.X509SanUri.NoValidation,
                SupportedClientIdScheme.X509SanDns.NoValidation,
            ),
        )

        val client = DocumentRetrieval(config)

        with(client) {
            val resolution =
                resolveRequestUri(
                    """
                    mdoc-openid4vp://https//walletcentric.signer.eudiw.dev/rp?request_uri=
                    https://walletcentric.signer.eudiw.dev/rp/wallet/sd/LAIfYMo0H4O3L8Ua9AQutH7IWPQxrXpaTb3IfoQNze0
                    &client_id=walletcentric.signer.eudiw.dev
                    """.trimIndent().replace("\n", ""),
                )

            if (resolution is Resolution.Success) {
                val documentsToSign = resolution.requestObject.documentLocations
                    .zip(resolution.requestObject.documentDigests) {
                            location, digest ->
                        DefaultHttpClientFactory().get(location.uri).let {
                            // read the response as a file to a byte array
                            val documentContent = it.readRawBytes()

                            // calculate the document digest using the hash algorithm OID from the request object
                            val messageDigest = MessageDigest.getInstance(resolution.requestObject.hashAlgorithmOID.value)

                            val computedDigest = messageDigest.digest(documentContent)
                            val base64Digest = String(Base64.getEncoder().encode(computedDigest))

                            // compare the calculated digest with the provided one
                            val validDigest = base64Digest == digest.hash

                            documentContent
                        }
                    }.map { it }

                // document signing flow starts here, as shown in the Example.kt file

                // the output of the  signing flow is a list of signed documents and a list of signatures

                val signedDocuments =
                    listOf(
                        ByteArrayInputStream("signed document".toByteArray()),
                    )
                val signatureList = SignaturesList(
                    listOf(
                        Signature("signature"),
                    ),
                )

                dispatch(
                    resolution.requestObject,
                    Consensus.Positive(
                        documentWithSignature = signedDocuments.map { it.readAllBytes().decodeToString() },
                        signatureObject = signatureList.signatures.map { it.value },
                    ),
                )
            }
        }
    }
}

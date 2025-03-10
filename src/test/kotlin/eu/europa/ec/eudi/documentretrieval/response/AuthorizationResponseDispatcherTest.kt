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
package eu.europa.ec.eudi.documentretrieval.response

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.documentretrieval.internal.request.asURL
import eu.europa.ec.eudi.documentretrieval.internal.response.DefaultDispatcher
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.SignatureQualifier
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class AuthorizationResponseDispatcherTest {

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `dispatch direct post response`() = runTest {
        fun test(state: String? = null) {
            val responseMode = ResponseMode.DirectPost("https://respond.here".asURL().getOrThrow())

            val requestObject =
                ResolvedRequestObject(
                    client = Client.Preregistered("https%3A%2F%2Fclient.example.org%2Fcb", "Verifier"),
                    nonce = "0S6_WzA2Mj",
                    responseMode = responseMode,
                    state = state,
                    signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                    documentDigests = listOf(
                        DocumentDigest(
                            hash = "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e",
                            label = "sample.pdf",
                        ),
                    ),
                    documentLocations = listOf(
                        DocumentLocation(
                            uri = URI("https://walletcentric.signer.eudiw.dev/rp/tester/document/sample.pdf").toURL(),
                            method = AccessMethod.Public,
                        ),
                    ),
                    hashAlgorithmOID = HashAlgorithmOID("2.16.840.1.101.3.4.2.1"),
                    clientData = "client data",
                )

            val consensus = Consensus.Positive(
                documentWithSignature = listOf("document with signature"),
                signatureObject = listOf("signature object"),
            )

            testApplication {
                externalServices {
                    hosts("https://respond.here") {
                        install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                            json()
                        }
                        routing {
                            post("/") {
                                val formParameters = call.receiveParameters()
                                val stateParam = formParameters["state"]
                                val documentWithSignature = formParameters["documentWithSignature"]
                                val signatureObject = formParameters["signatureObject"]

                                assertEquals(
                                    "application/x-www-form-urlencoded",
                                    call.request.headers["Content-Type"],
                                )
                                assertEquals(state, stateParam)
                                assertEquals("[\"document with signature\"]", documentWithSignature)
                                assertEquals("[\"signature object\"]", signatureObject)
                                assertNotNull(signatureObject)

                                call.respond(HttpStatusCode.OK)
                            }
                        }
                    }
                }

                val dispatcher = DefaultDispatcher {
                    createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }
                }

                val outcome = dispatcher.dispatch(
                    requestObject,
                    consensus,
                )

                assertIs<DispatchOutcome>(outcome)
            }
        }

        test(genState())
        test()
    }
}

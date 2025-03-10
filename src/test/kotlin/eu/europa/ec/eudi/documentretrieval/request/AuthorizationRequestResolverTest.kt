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
package eu.europa.ec.eudi.documentretrieval.request

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.documentretrieval.internal.request.DefaultAuthorizationRequestResolver
import eu.europa.ec.eudi.rqes.SignatureQualifier
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import net.minidev.json.JSONObject
import java.time.Clock
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals

class AuthorizationRequestResolverTest {

    private fun genState(): String {
        return State().value
    }

    @Test
    fun `resolve authorization request`() = runTest {
        fun test(state: String? = null) {
            val requestStr =
                """
                mdoc-openid4vp://walletcentric.signer.eudiw.dev?request_uri=
                https://walletcentric.signer.eudiw.dev/rp/wallet/sd/f759e624-026b-4610-be0a-c8dc82796fd0
                &client_id=f759e624-026b-4610-be0a-c8dc82796fd0
                """.trimIndent()

            val ecJWK: ECKey = ECKeyGenerator(Curve.P_256).keyID("123").generate()
            val ecPublicJWK: ECKey = ecJWK.toPublicJWK()

            testApplication {
                externalServices {
                    hosts("https://walletcentric.signer.eudiw.dev") {
                        install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) {
                            json()
                        }
                        routing {
                            get("/rp/wallet/sd/f759e624-026b-4610-be0a-c8dc82796fd0") {
                                val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT)
                                    .keyID(ecJWK.keyID).build()
                                val claimsSet = JWTClaimsSet.Builder().apply {
                                    claim("response_type", "code")
                                    claim("client_id", "f759e624-026b-4610-be0a-c8dc82796fd0")
                                    claim("response_mode", "direct_post")
                                    claim(
                                        "response_uri",
                                        "https://walletcentric.signer.eudiw.dev/rp/wallet/sd/upload/f759e624-026b-4610-be0a-c8dc82796fd0",
                                    )
                                    claim("nonce", "MmPDdW5BRJjtAcbNd_HPGhwBpDpvmMFBehJLbRCxl-o")
                                    claim("state", state)
                                    claim("signatureQualifier", "eu_eidas_qes")
                                    claim(
                                        "documentDigests",
                                        listOf(
                                            JSONObject().apply {
                                                put("hash", "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e")
                                                put("label", "sample.pdf")
                                            },
                                        ),
                                    )
                                    claim(
                                        "documentLocations",
                                        listOf(
                                            JSONObject().apply {
                                                put(
                                                    "uri",
                                                    "https://walletcentric.signer.eudiw.dev/rp/tester/document/sample.pdf",
                                                )
                                                put(
                                                    "method",
                                                    JSONObject().apply {
                                                        put("type", "public")
                                                    },
                                                )
                                            },
                                        ),
                                    )
                                    claim("hashAlgorithmOID", "2.16.840.1.101.3.4.2.1")
                                }.build()
                                val jwt = SignedJWT(header, claimsSet).apply { sign(ECDSASigner(ecJWK)) }

                                call.respondText(jwt.serialize(), io.ktor.http.ContentType.Any)
                            }
                        }
                    }
                }

                val config = DocumentRetrievalConfig(
                    jarConfiguration = JarConfiguration(
                        supportedAlgorithms = listOf(JWSAlgorithm.ES256),
                    ),
                    clock = Clock.systemDefaultZone(),
                    jarClockSkew = Duration.ofSeconds(15L),
                    supportedClientIdSchemes = listOf(
                        SupportedClientIdScheme.X509SanUri.NoValidation,
                        SupportedClientIdScheme.Preregistered(
                            clients = mapOf<String, PreregisteredClient>(
                                "f759e624-026b-4610-be0a-c8dc82796fd0" to PreregisteredClient(
                                    clientId = "f759e624-026b-4610-be0a-c8dc82796fd0",
                                    legalName = "walletcentric.signer.eudiw.dev",
                                    jarConfig = JWSAlgorithm.ES256 to JwkSetSource.ByValue(
                                        jwks = Json.parseToJsonElement(
                                            """
                                           {
                                               "keys": [
                                                   {
                                                       "kty": "${ecPublicJWK.keyType}",
                                                       "kid": "${ecPublicJWK.keyID}",
                                                       "crv": "${ecPublicJWK.curve}",
                                                       "x": "${ecPublicJWK.x}",
                                                       "y": "${ecPublicJWK.y}",
                                                       "d": "${ecPublicJWK.d}"
                                                   }
                                               ]
                                           }
                                            """.trimIndent(),
                                        ).jsonObject,
                                    ),
                                ),
                            ),
                        ),
                    ),
                )

                val resolveRequest = DefaultAuthorizationRequestResolver(config) {
                    createClient {
                        install(ContentNegotiation) {
                            json()
                        }
                    }
                }.resolveRequestUri(requestStr)

                require(resolveRequest is Resolution.Success)
                assertEquals(state, resolveRequest.requestObject.state)
                assertEquals(SignatureQualifier.EU_EIDAS_QES, resolveRequest.requestObject.signatureQualifier)
                assertEquals(
                    "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e",
                    resolveRequest.requestObject.documentDigests[0].hash,
                )
                assertEquals("sample.pdf", resolveRequest.requestObject.documentDigests[0].label)
            }
        }

        test(genState())
        test()
    }
}

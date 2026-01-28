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
package eu.europa.ec.eudi.documentretrieval

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.rqes.JsonSupport
import eu.europa.ec.eudi.rqes.KtorHttpClientFactory
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertNotNull

internal class DocumentRetrievalTest {

    @Test
    fun `DocumentRetrieval invoke with default HttpClientFactory returns non-null instance`() {
        val config = getConfig()
        val documentRetrieval = DocumentRetrieval(config)
        assertNotNull(documentRetrieval)
    }

    @Test
    fun `DocumentRetrieval invoke with custom HttpClientFactory returns non-null instance`() {
        val config = getConfig()
        val customHttpClientFactory: KtorHttpClientFactory = {
            HttpClient(OkHttp) {
                install(ContentNegotiation) {
                    json(
                        json = JsonSupport,
                    )
                }
                install(Logging) {
                    level = LogLevel.ALL
                }
            }
        }
        val documentRetrieval = DocumentRetrieval(config, customHttpClientFactory)
        assertNotNull(documentRetrieval)
    }

    internal fun getConfig(): DocumentRetrievalConfig = DocumentRetrievalConfig(
        supportedClientIdSchemes = listOf(
            SupportedClientIdScheme.X509SanUri.NoValidation,
            SupportedClientIdScheme.Preregistered(
                clients = mapOf<String, PreregisteredClient>(
                    "16b45b1e-3253-436d-a5ef-c235c3f61075" to PreregisteredClient(
                        clientId = "16b45b1e-3253-436d-a5ef-c235c3f61075",
                        legalName = "walletcentric.signer.eudiw.dev",
                        jarConfig = JWSAlgorithm.HS256 to JwkSetSource.ByValue(
                            jwks = Json.parseToJsonElement(
                                """
                                   {
                                       "keys": [
                                           {
                                               "kty": "oct",
                                               "use": "sig",
                                               "alg": "HS256",
                                               "k": "U0mY7v8Q1w2Z4v6y9B+D-KaPdSgVkXpA"
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
}

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
import eu.europa.ec.eudi.rqes.*
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.net.URI
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private fun getUnsafeOkHttpClient(): OkHttpClient {
    // Create a trust manager that does not validate certificate chains
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        }

        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    })

    // Install the all-trusting trust manager
    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    // Create an ssl socket factory with our all-trusting manager
    val sslSocketFactory = sslContext.socketFactory

    return OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }.build()
}

private val unsafeHttpClientFactory: KtorHttpClientFactory = {
    HttpClient(OkHttp) {
        install(ContentNegotiation) {
            json(
                json = JsonSupport,
            )
        }

        engine {
            preconfigured = getUnsafeOkHttpClient()
        }
    }
}

private var cscClientConfig = CSCClientConfig(
    OAuth2Client.Confidential.PasswordProtected("wallet-private", "8aEtqVYjtvmvGPSpbxOyjhiOAC285pdE"),
    URI("https://localhost:3000/api/callback"),
    ParUsage.IfSupported,
)

fun main() {
    runBlocking {
        val rssp = RSSPId("https://localhost:3000/api/csc/v2").getOrThrow()

        // Retrieve the RSSP metadata
        val rsspMetadata = RSSPMetadataResolver(unsafeHttpClientFactory).resolve(rssp, Locale.ENGLISH).getOrThrow()

        // create the CSC client
        val cscClient: CSCClient = CSCClient.oauth2(
            cscClientConfig,
            rsspMetadata,
            unsafeHttpClientFactory,
        ).getOrThrow()

        with(cscClient) {
            val serverState = UUID.randomUUID().toString()

            val authorizedServiceRequest = authorizeWithClientCredentials().getOrThrow()

            // retrieve the credentials from the RSSP
            val credentials = with(authorizedServiceRequest) {
                listCredentials(CredentialsListRequest()).getOrThrow().also { println(it) }
            }

            val documents = DocumentList(
                listOf(DocumentDigest(Digest("sdfhklyu2348ojfsd"), "My loan contract")),
                HashAlgorithmOID.SHA256RSA,
            )

            // initiate the credential authorization request flow
            val credAuthRequestPrepared = with(authorizedServiceRequest) {
                prepareCredentialAuthorizationRequest(credentials.first(), documents).getOrThrow()
            }

            println("Use the following URL to authenticate:")
            println(credAuthRequestPrepared.value.authorizationCodeURL)

            val credentialAuthorizationCode = AuthorizationCode(readlnOrNull()!!)

            // provide the credential authorization code to the CSC client
            val credentialAuthorized = with(credAuthRequestPrepared) {
                authorizeWithAuthorizationCode(
                    credentialAuthorizationCode,
                    serverState,
                ).getOrThrow()
            }

            println("Authorized credential request:")
            println(credentialAuthorized)

            require(credentialAuthorized is CredentialAuthorized.SCAL2) { "Expected SCAL2" }

            val signatures = with(credentialAuthorized) {
                signHash(AlgorithmOID.ECDSA_SHA256).getOrThrow()
            }

            println("Signatures: $signatures")
        }
    }
}

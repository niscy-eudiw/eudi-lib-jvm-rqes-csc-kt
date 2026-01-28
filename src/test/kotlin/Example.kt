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
import eu.europa.ec.eudi.rqes.*
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.net.URI
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

val client_id = "wallet-client-tester"
val client_secret = "somesecrettester2"

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
        install(Logging) {
            level = LogLevel.ALL
        }

        engine {
            preconfigured = getUnsafeOkHttpClient()
        }
    }
}

private var cscClientConfig = CSCClientConfig(
    OAuth2Client.Confidential.ClientSecretBasic(client_id, client_secret),
    URI("https://oauthdebugger.com/debug"),
    ParUsage.IfSupported,
    RarUsage.IfSupported,
)

fun main() {
    runBlocking {
        // create the CSC client
        val cscClient: CSCClient = CSCClient.oauth2(
            cscClientConfig,
            "https://walletcentric.signer.eudiw.dev/csc/v2",
            unsafeHttpClientFactory,
        ).getOrThrow()

        val rsspMetadata = cscClient.rsspMetadata

        with(cscClient) {
            var walletState = UUID.randomUUID().toString()

            // initiate the service authorization request
            val serviceAuthRequestPrepared = prepareServiceAuthorizationRequest(walletState).getOrThrow()

            println("Use the following URL to authenticate:\n${serviceAuthRequestPrepared.value.authorizationCodeURL}")
            println("Enter the service authorization code:")
            val serviceAuthorizationCode = AuthorizationCode(readln())

            val authorizedServiceRequest = with(serviceAuthRequestPrepared) {
                // provide the authorization code to the client
                authorizeWithAuthorizationCode(serviceAuthorizationCode, walletState).getOrThrow()
            }

            // retrieve the list of credentials from the RSSP
            val credentials = with(authorizedServiceRequest) {
                listCredentials(CredentialsListRequest()).getOrThrow()
            }

            // old (r3)
//            val documentToSign = DocumentToSign(
//                Document(
//                    File(ClassLoader.getSystemResource("sample.pdf").path),
//                    "A sample pdf",
//                ),
//                SignatureFormat.P,
//                ConformanceLevel.ADES_B_B,
//                SigningAlgorithmOID.RSA,
//                SignedEnvelopeProperty.ENVELOPED,
//                ASICContainer.NONE,
//            )

            // new (R5)
            val documentToSign = DocumentToSign(
                "/storage/emulated/0/Android/data/com.example.demorqesmobile/files/Documents/sample.pdf", // input path
                "/storage/emulated/0/Android/data/com.example.demorqesmobile/files/Documents/signed-sample.pdf", // output path
                "A sample pdf",
                SignatureFormat.P,
                ConformanceLevel.ADES_B_B,
                SignedEnvelopeProperty.ENVELOPED,
                ASICContainer.NONE,
            )

            walletState = UUID.randomUUID().toString()

            // calculate the hash of the document to sign
            val documentDigests = calculateDocumentHashes(
                listOf(documentToSign),
                credentials.first().certificate,
                HashAlgorithmOID.SHA_256,
            )

            // initiate the credential authorization request flow, using the hashes calculated above
            val credAuthRequestPrepared = prepareCredentialAuthorizationRequest(
                CredentialAuthorizationSubject(
                    CredentialRef.ByCredentialID(credentials.first().credentialID),
                    documentDigests,
                    1,
                ),
                walletState,
            ).getOrThrow()

            println("Use the following URL to authenticate:\n${credAuthRequestPrepared.authorizationRequestPrepared.authorizationCodeURL}")
            println("Enter the credential authorization code:")
            val credentialAuthorizationCode = AuthorizationCode(readln())

            // provide the credential authorization code to the CSC client
            val credentialAuthorized = with(credAuthRequestPrepared) {
                authorizeWithAuthorizationCode(
                    credentialAuthorizationCode,
                    walletState,
                ).getOrThrow()
            }

            require(credentialAuthorized is CredentialAuthorized.SCAL2)

            with(credentialAuthorized) {
                // sign the hashes of the documents
                val signatures = signHash(SigningAlgorithmOID.RSA).getOrThrow()

                // createSignedDocuments creates the signed files on disk (new R5)
                createSignedDocuments(signatures.signatures)
            }

            // The signed document should now be available at the output path specified in documentToSign
            println("Document signing completed. Check the output path for the signed document.")
        }
    }
}

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
package eu.europa.ec.eudi.rqes

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import org.jsoup.Jsoup
import java.io.File
import java.net.URI
import java.util.*
import kotlin.test.assertTrue
import kotlin.time.Duration

class DocumentSigningFlowIT {

    // @Test
    fun `successful document signing cycle`() = runTest(timeout = Duration.parse("1m")) {
        val httpClient: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = JsonSupport,
                    )
                }
                install(HttpRedirect) {
                    checkHttpMethod = false
                }
                install(HttpCookies) {
                    storage = AcceptAllCookiesStorage()
                }
            }
        }

        val cscClientConfig = CSCClientConfig(
            OAuth2Client.Confidential.ClientSecretBasic("wallet-client-tester", "somesecrettester2"),
            URI("https://oauthdebugger.com/debug"),
            ParUsage.IfSupported,
            RarUsage.IfSupported,
            includeRevocationInfo = false,
        )

        val cscClient: CSCClient = CSCClient.oauth2(
            cscClientConfig,
            "https://walletcentric.signer.eudiw.dev/csc/v2",
            httpClient,
        ).getOrThrow()

        with(cscClient) {
            var walletState = UUID.randomUUID().toString()

            // initiate the service authorization request
            val serviceAuthRequestPrepared = prepareServiceAuthorizationRequest(walletState).getOrThrow()

            val (serviceAuthorizationCode) = getCodeAndState(
                serviceAuthRequestPrepared.value.authorizationCodeURL,
                httpClient(),
            )

            val authorizedServiceRequest = with(serviceAuthRequestPrepared) {
                // provide the authorization code to the client
                authorizeWithAuthorizationCode(AuthorizationCode(serviceAuthorizationCode), walletState).getOrThrow()
            }

            // retrieve the list of credentials from the RSSP
            val credentials = with(authorizedServiceRequest) {
                listCredentials(CredentialsListRequest()).getOrThrow()
            }

            val documentToSign = DocumentToSign(
                documentInputPath = ClassLoader.getSystemResource("sample.pdf").path,
                documentOutputPath = "signed_sample.pdf",
                label = "A sample pdf",
                signatureFormat = SignatureFormat.P,
                conformanceLevel = ConformanceLevel.ADES_B_B,
                signedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPED,
                asicContainer = ASICContainer.NONE,
            )

            walletState = UUID.randomUUID().toString()

            // calculate the hash of the document to sign
            val documentDigests: DocumentDigestList = calculateDocumentHashes(
                listOf(documentToSign),
                credentials.first().certificate,
                HashAlgorithmOID.SHA_256,
            )

            // initiate the credential authorization request flow, using the hashes calculated above
            val credAuthRequestPrepared: CredentialAuthorizationRequestPrepared = prepareCredentialAuthorizationRequest(
                CredentialAuthorizationSubject(
                    CredentialRef.ByCredentialID(credentials.first().credentialID),
                    documentDigests,
                    1,
                ),
                walletState,
            ).getOrThrow()

            val (credentialAuthorizationCode) = getCodeAndState(
                credAuthRequestPrepared.authorizationRequestPrepared.authorizationCodeURL,
                httpClient(),
            )

            // provide the credential authorization code to the CSC client
            val credentialAuthorized = with(credAuthRequestPrepared) {
                authorizeWithAuthorizationCode(
                    AuthorizationCode(credentialAuthorizationCode),
                    walletState,
                ).getOrThrow()
            }

            require(credentialAuthorized is CredentialAuthorized.SCAL2)

            val signatures = with(credentialAuthorized) {
                // sign the hashes of the documents
                val signatures = signHash(SigningAlgorithmOID.RSA).getOrThrow()

                // createSignedDocuments creates the signed files on disk (returns Unit)
                createSignedDocuments(signatures.signatures)

                signatures // Return signatures to use for verification
            }

            // Since createSignedDocuments creates files on disk, we can check if the signing process completed
            assertTrue(signatures.signatures.isNotEmpty()) // Just verify the signing process completed
        }
    }

    private suspend fun getCodeAndState(authorizationURL: HttpsUrl, httpClient: HttpClient): Pair<String, String> {
        // do a request with ktor to the authorizationURL
        val response = httpClient.get(authorizationURL.value)
        val responseBody: String = response.bodyAsText()

        // Parse the login form using Jsoup
        val document = Jsoup.parse(responseBody)
        val form = document.selectFirst("form") ?: throw IllegalStateException("Form not found")

        val formAction: String = form.attr("action")

        val formData = mutableMapOf<String, String>()
        form.select("input").forEach { input ->
            when (input.attr("name")) {
                "username" -> formData["username"] = "8PfCAQzTmON+FHDvH4GW/g+JUtg5eVTgtqMKZFdB/+c=;FirstName;TesterUser"
                "password" -> formData["password"] = "5adUg@35Lk_Wrm3"
                else -> formData[input.attr("name")] = input.attr("value")
            }
        }

        // Perform POST request with the filled form data
        httpClient.submitForm(
            url = "https://walletcentric.signer.eudiw.dev$formAction",
            formParameters = Parameters.build {
                formData.forEach { (key, value) ->
                    append(key, value)
                }
            },
        )

        val response2 = httpClient.get(authorizationURL.value)
        // get code and state from the url query params
        val code = response2.request.url.parameters["code"]
        val state = response2.request.url.parameters["state"]

        return code!! to state!!
    }
}

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
package eu.europa.ec.eudi.rqes

import eu.europa.ec.eudi.rqes.internal.asMetadata
import io.ktor.http.*
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.util.*
import javax.security.auth.x500.X500Principal

object SampleRSSP {
    val Id: RSSPId = RSSPId("https://rssp.example.com/csc/v2").getOrThrow()
}

internal fun mockPublicClient(
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
    tsaurl: String? = URI("http://ts.cartaodecidadao.pt/tsa/server").toString(),
    includeRevocationInfo: Boolean = false,
) =
    mockClient(
        OAuth2Client.Public("client-id"),
        ktorHttpClientFactory,
        parUsage,
        rarUsage,
        tsaurl,
        includeRevocationInfo,
    )

internal fun mockConfidentialClient(
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
    tsaurl: String? = URI("http://ts.cartaodecidadao.pt/tsa/server").toString(),
    includeRevocationInfo: Boolean = false,
) = mockClient(
    OAuth2Client.Confidential.ClientSecretPost("client-id", "secret"),
    ktorHttpClientFactory,
    parUsage,
    rarUsage,
    tsaurl,
    includeRevocationInfo,
)

private fun mockClient(
    oauth2Client: OAuth2Client,
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
    tsaurl: String? = URI("http://ts.cartaodecidadao.pt/tsa/server").toString(),
    includeRevocationInfo: Boolean = false,
) = CSCClient.oauth2(
    rsspMetadata = rsspMetadata(),
    cscClientConfig = CSCClientConfig(
        oauth2Client,
        URI("https://example.com/redirect"),
        parUsage,
        rarUsage,
        tsaurl = tsaurl,
        includeRevocationInfo = includeRevocationInfo,
    ),
    ktorHttpClientFactory = ktorHttpClientFactory,
).getOrThrow()

internal fun RSSPId.info() = HttpsUrl(
    URLBuilder(toString()).appendPathSegments("/info", encodeSlash = false).buildString(),
).getOrThrow()

/**
 * Gets the [RSSPMetadata] used throughout the tests.
 */
internal fun rsspMetadata() = RSSPMetadata(
    rsspId = SampleRSSP.Id,
    specs = "2.0.0.0",
    name = "ACME Trust Services",
    logo = URI("https://service.domain.org/images/logo.png"),
    region = "IT",
    lang = Locale.forLanguageTag("en-US"),
    description = "An efficient remote signature service",
    authTypes = setOf(
        AuthType.Basic,
        AuthType.OAuth2(setOf(authorizationServerMetadata)),
    ),

    methods = methods,
)

private val methods = listOf(
    RSSPMethod.AuthLogin,
    RSSPMethod.AuthRevoke,
    RSSPMethod.CredentialsList,
    RSSPMethod.CredentialsInfo,
    RSSPMethod.CredentialsAuthorize,
    RSSPMethod.CredentialsSendOTP,
    RSSPMethod.SignaturesSignHash,
)

private val authorizationServerMetadata =
    asMetadata(HttpsUrl("https://auth.domain.org").getOrThrow())

internal val mockServiceAccessAuthorized = ServiceAccessAuthorized(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
)

internal fun mockCredentialAuthorizedSCAL1() = CredentialAuthorized.SCAL1(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
    mockCredential.credentialID,
    mockCredential.certificate,
)

internal fun mockCredentialAuthorizedSCAL2() = CredentialAuthorized.SCAL2(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
    mockCredential.credentialID,
    mockCredential.certificate,
    mockDocumentDigestList,
)

internal val mockCredential = CredentialInfo(
    CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"),
    CredentialDescription("Test credential"),
    SignatureQualifier("eu_eidas_qes"),
    CredentialKey(
        CredentialKeyStatus.Enabled,
        listOf(SigningAlgorithmOID.RSA),
        2048,
        null,
    ),
    CredentialCertificate(
        status = CredentialCertificateStatus.Valid,
        certificates = listOf(
            run {
                val certificateBytes: ByteArray = Base64.getDecoder().decode(
                    """
                        MIIDZDCCAuqgAwIBAgIUMFrstjahbrxp7w4ok1mScfbilBwwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBD
                        QSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X
                        DTI0MTAyMTE0MTE0M1oXDTI2MTAyMTE0MTE0MlowVTEdMBsGA1UEAwwURmlyc3ROYW1lIFRlc3RlclVzZXIxEzARBgNVBAQM
                        ClRlc3RlclVzZXIxEjAQBgNVBCoMCUZpcnN0TmFtZTELMAkGA1UEBhMCRkMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                        AoIBAQChx+kEQrJbwL+1y1BSALT+XorS3AMU2LioWWBn2NW8sMmybhPI+5rzZA1zwldGm+ibDgfenxBZzSKCHzqSi7jRzlxA
                        I1vKNxE+fzpx9gfCKXvHwbCFTi2vS4YLpPuMy6irjCOJ5c2paciWVdL9k7MRSZz906YzU/j0N5hIE15asz5X5fGxq+mXr8V+
                        UXYZddgiJMFKRcyg1UGoyLpXdBrscMVH5fpbEJXwhdadjmORMed7JbBxGLQrzHqCrJM6SPn5ONXJsfkm1JPXBQUgleaTS3hx
                        FTm3+qql8GC7h1wHZ+3DscnM32tTx1SJtUK9pg6IvWHlxodT5iRKg5Lu5N9vAgMBAAGjgcUwgcIwDAYDVR0TAQH/BAIwADAf
                        BgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwQwYDVR0fBDww
                        OjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9VVF8wMS5jcmwwHQYDVR0OBBYEFMSf
                        REXHBB5/QOShd41wc7hds+g6MA4GA1UdDwEB/wQEAwIGQDAKBggqhkjOPQQDAgNoADBlAjBExuJApXiH8ydkCOZV9M+jO2Rm
                        3vam03nsKvDBJ8pwus6n4IebetX6aHgue7WztGoCMQCI7vDaejO5mCgJGK6f/78onRQI6bm9/VWZnM6DSAnZ/gzQFC4EnJh4
                        cePfOzgUEjU=
                    """.trimIndent().replace("\n", ""),
                )
                val inputStream = ByteArrayInputStream(certificateBytes)
                val x509CertificateFactory = CertificateFactory.getInstance("X.509")
                x509CertificateFactory.generateCertificate(inputStream) as X509Certificate
            },

            run {
                val certificateBytes: ByteArray = Base64.getDecoder().decode(
                    """
                        MIIDHTCCAqOgAwIBAgIUVqjgtJqf4hUYJkqdYzi+0xwhwFYwCgYIKoZIzj0EAwMwXDEeMBwGA1UEAwwVUElEIElzc3VlciBD
                        QSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X
                        DTIzMDkwMTE4MzQxN1oXDTMyMTEyNzE4MzQxNlowXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQK
                        DCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMHYwEAYHKoZIzj0CAQYFK4EEACID
                        YgAEFg5Shfsxp5R/UFIEKS3L27dwnFhnjSgUh2btKOQEnfb3doyeqMAvBtUMlClhsF3uefKinCw08NB31rwC+dtj6X/LE3n2
                        C9jROIUN8PrnlLS5Qs4Rs4ZU5OIgztoaO8G9o4IBJDCCASAwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSzbLiR
                        FxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXBy
                        b2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUs2y4kRcc16QaZjGHQuGLwEDMlRswDgYD
                        VR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9h
                        cmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDaAAwZQIwaXUA3j++xl/tdD76tXEWCikf
                        M1CaRz4vzBC7NS0wCdItKiz6HZeV8EPtNCnsfKpNAjEAqrdeKDnr5Kwf8BA7tATehxNlOV4Hnc10XO1XULtigCwb49RpkqlS
                        2Hul+DpqObUs
                    """.trimIndent().replace("\n", ""),
                )
                val inputStream = ByteArrayInputStream(certificateBytes)
                val x509CertificateFactory = CertificateFactory.getInstance("X.509")
                x509CertificateFactory.generateCertificate(inputStream) as X509Certificate
            },
        ),
        rawCertificates = listOf(
            """
                MIIDZDCCAuqgAwIBAgIUMFrstjahbrxp7w4ok1mScfbilBwwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBD
                QSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X
                DTI0MTAyMTE0MTE0M1oXDTI2MTAyMTE0MTE0MlowVTEdMBsGA1UEAwwURmlyc3ROYW1lIFRlc3RlclVzZXIxEzARBgNVBAQM
                ClRlc3RlclVzZXIxEjAQBgNVBCoMCUZpcnN0TmFtZTELMAkGA1UEBhMCRkMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                AoIBAQChx+kEQrJbwL+1y1BSALT+XorS3AMU2LioWWBn2NW8sMmybhPI+5rzZA1zwldGm+ibDgfenxBZzSKCHzqSi7jRzlxA
                I1vKNxE+fzpx9gfCKXvHwbCFTi2vS4YLpPuMy6irjCOJ5c2paciWVdL9k7MRSZz906YzU/j0N5hIE15asz5X5fGxq+mXr8V+
                UXYZddgiJMFKRcyg1UGoyLpXdBrscMVH5fpbEJXwhdadjmORMed7JbBxGLQrzHqCrJM6SPn5ONXJsfkm1JPXBQUgleaTS3hx
                FTm3+qql8GC7h1wHZ+3DscnM32tTx1SJtUK9pg6IvWHlxodT5iRKg5Lu5N9vAgMBAAGjgcUwgcIwDAYDVR0TAQH/BAIwADAf
                BgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwQwYDVR0fBDww
                OjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9VVF8wMS5jcmwwHQYDVR0OBBYEFMSf
                REXHBB5/QOShd41wc7hds+g6MA4GA1UdDwEB/wQEAwIGQDAKBggqhkjOPQQDAgNoADBlAjBExuJApXiH8ydkCOZV9M+jO2Rm
                3vam03nsKvDBJ8pwus6n4IebetX6aHgue7WztGoCMQCI7vDaejO5mCgJGK6f/78onRQI6bm9/VWZnM6DSAnZ/gzQFC4EnJh4
                cePfOzgUEjU=
            """.trimIndent().replace("\n", ""),
            """
                MIIDHTCCAqOgAwIBAgIUVqjgtJqf4hUYJkqdYzi+0xwhwFYwCgYIKoZIzj0EAwMwXDEeMBwGA1UEAwwVUElEIElzc3VlciBD
                QSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X
                DTIzMDkwMTE4MzQxN1oXDTMyMTEyNzE4MzQxNlowXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQK
                DCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMHYwEAYHKoZIzj0CAQYFK4EEACID
                YgAEFg5Shfsxp5R/UFIEKS3L27dwnFhnjSgUh2btKOQEnfb3doyeqMAvBtUMlClhsF3uefKinCw08NB31rwC+dtj6X/LE3n2
                C9jROIUN8PrnlLS5Qs4Rs4ZU5OIgztoaO8G9o4IBJDCCASAwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBSzbLiR
                FxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXBy
                b2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUs2y4kRcc16QaZjGHQuGLwEDMlRswDgYD
                VR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9h
                cmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDaAAwZQIwaXUA3j++xl/tdD76tXEWCikf
                M1CaRz4vzBC7NS0wCdItKiz6HZeV8EPtNCnsfKpNAjEAqrdeKDnr5Kwf8BA7tATehxNlOV4Hnc10XO1XULtigCwb49RpkqlS
                2Hul+DpqObUs
            """.trimIndent().replace("\n", ""),
        ),
        issuerDN = X500Principal("C=UT, O=EUDI Wallet Reference Implementation, CN=PID Issuer CA - UT 01"),
        serialNumber = "276059244570899245834283519267490992286096069660",
        subjectDN = X500Principal("C=FC, GIVENNAME=FirstName, SURNAME=TesterUser, CN=FirstName TesterUser"),
        validFrom = LocalDateTime.now().minusDays(1),
        validTo = LocalDateTime.now().plusYears(1),
    ),
    CredentialAuthorization.OAuth2Code(AuthorizationMode.OAuth2Code),
    SCAL.Two,
    1,
    "en-US",
)

internal val mockDocumentDigestList = DocumentDigestList(
    hashAlgorithmOID = HashAlgorithmOID.SHA_256,
    hashCalculationTime = Instant.now(),
    documentDigests = listOf(
        DocumentDigest(
            hash = Digest.Base64Digest("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="),
            label = "Test document",
        ),
    ),
)

internal val mockDocumentsToSign = listOf(
    DocumentToSign(
        documentInputPath = ClassLoader.getSystemResource("sample.pdf").path,
        documentOutputPath = "signed_sample.pdf",
        label = "test.pdf",
        signatureFormat = SignatureFormat.P,
        conformanceLevel = ConformanceLevel.ADES_B_B,
        signedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPED,
        asicContainer = ASICContainer.NONE,
    ),
)

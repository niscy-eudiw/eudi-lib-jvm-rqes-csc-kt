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

import com.nimbusds.oauth2.sdk.GrantType
import eu.europa.ec.eudi.rqes.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

internal class DefaultRSSPMetadataResolverTest {

    @Test
    fun `resolution success with oauth2 base url`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_valid.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val metaData =
            assertDoesNotThrow { resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US")).getOrThrow() }

        val oauth2AuthType = metaData.oauth2AuthType()
        assertNotNull(oauth2AuthType, "OAuth2 auth type should be present")

        assertEquals(SampleRSSP.Id, metaData.rsspId)
        // Verify authorization endpoint URIs
        assertEquals(
            "https://auth.domain.org/oauth2/authorize",
            oauth2AuthType.authorizationServers.elementAt(0).authorizationEndpointURI.toString(),
            "First server should have correct authorization endpoint",
        )
        assertEquals(false, oauth2AuthType.authorizationServers.elementAt(0).supportsRar())
    }

    @Test
    fun `resolution success with oauth2 issuer`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_valid_with_oauth2issuer.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val metaData =
            assertDoesNotThrow { resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US")).getOrThrow() }

        val oauth2AuthType = metaData.oauth2AuthType()
        assertNotNull(oauth2AuthType, "OAuth2 auth type should be present")

        assertEquals(SampleRSSP.Id, metaData.rsspId)
        assertEquals(SampleRSSP.Id, metaData.rsspId)
        // Verify authorization endpoint URIs
        assertEquals(
            "https://auth.domain.org/protocol/openid-connect/auth",
            oauth2AuthType.authorizationServers.elementAt(0).authorizationEndpointURI.toString(),
            "First server should have correct authorization endpoint",
        )
        assertEquals(false, oauth2AuthType.authorizationServers.elementAt(0).supportsRar())
    }

    @Test
    fun `resolution success with oauth2 servers`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_valid_with_oauth2servers.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val metaData =
            assertDoesNotThrow { resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US")).getOrThrow() }

        assertEquals(SampleRSSP.Id, metaData.rsspId)

        // Verify OAuth2 auth type with multiple servers
        val oauth2AuthType = metaData.oauth2AuthType()
        assertNotNull(oauth2AuthType, "OAuth2 auth type should be present")

        assertEquals(2, oauth2AuthType.authorizationServers.size, "Should have 2 authorization servers")
        assertTrue(oauth2AuthType.authorizationServers.first().grantTypes.contains(GrantType.AUTHORIZATION_CODE))
        assertEquals(false, oauth2AuthType.authorizationServers.elementAt(0).supportsRar())
        assertEquals(true, oauth2AuthType.authorizationServers.elementAt(1).supportsRar())

        // Verify authorization endpoint URIs
        assertEquals(
            "https://auth.domain.org/oauth2/authorize",
            oauth2AuthType.authorizationServers.elementAt(0).authorizationEndpointURI.toString(),
            "First server should have correct authorization endpoint",
        )
        assertEquals(
            "https://auth.domain.org/protocol/openid-connect/auth",
            oauth2AuthType.authorizationServers.elementAt(1).authorizationEndpointURI.toString(),
            "Second server should have correct authorization endpoint",
        )

        // Verify token endpoint URIs
        assertEquals(
            "https://auth.domain.org/oauth2/token",
            oauth2AuthType.authorizationServers.elementAt(0).tokenEndpointURI.toString(),
            "First server should have correct authorization endpoint",
        )
        assertEquals(
            "https://auth.domain.org/protocol/openid-connect/token",
            oauth2AuthType.authorizationServers.elementAt(1).tokenEndpointURI.toString(),
            "Second server should have correct authorization endpoint",
        )
    }

    @Test
    fun `resolution fails when oauth2Servers and top-level supportsRar are both present`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_with_oauth2servers_and_top_level_supports_rar.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }

    @Test
    fun `resolution fails when specs is not 2_2_0_0`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_specs.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }

    @Test
    fun `resolution fails when oauth2Servers and oauth2 or oauth2Issuer are both present`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_with_oauth2servers_and_oauth2issuer.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }

    @Test
    fun `resolution fails when oauth2 parameter exists but authType is missing oauth2 value`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_with_oauth2_but_missing_oauth2_authtype.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }

    @Test
    fun `resolution fails when oauth2 is required but none of the 3 params are present`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_missing_oauth2_params_when_oauth2_required.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }

    @Test
    fun `resolution fails when oauth2Server authType contains invalid value`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialIssuerMetaDataHandler(
                SampleRSSP.Id,
                "eu/europa/ec/eudi/rqes/internal/rssp_metadata_invalid_oauth2server_authtype.json",
            ),
        )

        val resolver = RSSPMetadataResolver(
            mockedKtorHttpClientFactory,
        )
        val result = resolver.resolve(SampleRSSP.Id, Locale.forLanguageTag("en-US"))
        assertTrue(result.isFailure, "Resolution should fail")
    }
}

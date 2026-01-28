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
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals

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

        assertEquals(SampleRSSP.Id, metaData.rsspId)
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

        assertEquals(SampleRSSP.Id, metaData.rsspId)
    }
}

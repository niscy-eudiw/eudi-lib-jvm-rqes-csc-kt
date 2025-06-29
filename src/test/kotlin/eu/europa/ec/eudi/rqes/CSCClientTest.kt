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

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import kotlin.test.Test

class CSCClientTest {

    @Test
    fun `create with RSSP Id`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetaDataHandler(SampleRSSP.Id, "eu/europa/ec/eudi/rqes/internal/rssp_metadata_valid.json"),
            authServerWellKnownMocker(),
        )

        assertDoesNotThrow {
            CSCClient.oauth2(
                rsspId = SampleRSSP.Id.toString(),
                cscClientConfig = CSCClientConfig(
                    OAuth2Client.Public("client-id"),
                    URI("https://example.com/redirect"),
                    URI("https://walletcentric.signer.eudiw.dev").toURL(),
                    ParUsage.Never,
                    RarUsage.Never,
                    tsaurl = URI("http://ts.cartaodecidadao.pt/tsa/server").toString()
                ),
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()
        }
    }

    @Test
    fun `create with metadata`() = runTest {
        assertDoesNotThrow {
            CSCClient.oauth2(
                rsspMetadata = rsspMetadata(),
                cscClientConfig = CSCClientConfig(
                    OAuth2Client.Public("client-id"),
                    URI("https://example.com/redirect"),
                    URI("https://walletcentric.signer.eudiw.dev").toURL(),
                    ParUsage.Never,
                    RarUsage.Never,
                ),
                ktorHttpClientFactory = DefaultHttpClientFactory,
            ).getOrThrow()
        }
    }
}

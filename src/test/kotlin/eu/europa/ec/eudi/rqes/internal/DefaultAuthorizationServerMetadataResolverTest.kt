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
package eu.europa.ec.eudi.rqes.internal

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.RequestMocker
import eu.europa.ec.eudi.rqes.jsonResponse
import eu.europa.ec.eudi.rqes.match
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertIs

internal class DefaultAuthorizationServerMetadataResolverTest {

    @Test
    internal fun `resolution success with compliant oidc well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm")
            .getOrThrow()

        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create("https://keycloak-eudi.netcompany-intrasoft.com/.well-known/openid-configuration/realms/pid-issuer-realm"),
                ),
                jsonResponse("eu/europa/ec/eudi/rqes/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val metadata = resolver.resolve(issuer).getOrThrow()

        assertIs<OIDCProviderMetadata>(metadata)
    }

    @Test
    internal fun `resolution success with compliant oauth2 well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm")
            .getOrThrow()

        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create(
                        "https://keycloak-eudi.netcompany-intrasoft.com/.well-known/oauth-authorization-server/realms/pid-issuer-realm",
                    ),
                ),
                jsonResponse("eu/europa/ec/eudi/rqes/internal/oauth_authorization_server_metadata.json"),
            ),
        )
        val metadata = resolver.resolve(issuer).getOrThrow()

        assertIs<AuthorizationServerMetadata>(metadata)
    }
}

private fun mockResolver(mocker: RequestMocker) =
    AuthorizationServerMetadataResolver(mockedKtorHttpClientFactory(mocker))

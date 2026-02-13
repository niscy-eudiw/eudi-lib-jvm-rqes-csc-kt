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

import com.nimbusds.oauth2.sdk.GrantType
import eu.europa.ec.eudi.podofomanager.PodofoManager
import eu.europa.ec.eudi.rqes.internal.*
import eu.europa.ec.eudi.rqes.internal.http.*

interface CSCClient :
    AuthorizeService,
    AuthorizeCredential,
    ListCredentials,
    GetCredentialInfo,
    SignHash,
    SignDoc,
    CreateSignedDocuments,
    CalculateDocumentHashes {

    val rsspMetadata: RSSPMetadata

    companion object {
        suspend fun oauth2(
            cscClientConfig: CSCClientConfig,
            rsspId: String,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<CSCClient> = kotlin.runCatching {
            val metadata =
                run {
                    val id = RSSPId(rsspId).getOrThrow()
                    val resolver = RSSPMetadataResolver(ktorHttpClientFactory)
                    resolver.resolve(id, cscClientConfig.locale).getOrThrow()
                }
            oauth2(cscClientConfig, metadata, ktorHttpClientFactory).getOrThrow()
        }

        fun oauth2(
            cscClientConfig: CSCClientConfig,
            rsspMetadata: RSSPMetadata,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<CSCClient> = runCatching {
            val podofoManager = PodofoManager()
            val oauth2AuthType =
                requireNotNull(rsspMetadata.oauth2AuthType()) { "RSSP doesn't support OAUTH2" }
            val authServerMetadata = oauth2AuthType.authorizationServers.first()

            val tokenEndpointClient = TokenEndpointClient(
                checkNotNull(authServerMetadata.tokenEndpointURI).toURL(),
                cscClientConfig,
                ktorHttpClientFactory,
            )

            val authorizationEndpointClient =
                if (GrantType.AUTHORIZATION_CODE in authServerMetadata.grantTypes) {
                    AuthorizationEndpointClient(
                        checkNotNull(authServerMetadata.authorizationEndpointURI).toURL(),
                        authServerMetadata.pushedAuthorizationRequestEndpointURI?.toURL(),
                        cscClientConfig,
                        ktorHttpClientFactory,
                    )
                } else null

            val authorizeServiceImpl = AuthorizeServiceImpl(
                authorizationEndpointClient,
                tokenEndpointClient,
            )

            val credentialsInfoEndpointClient =
                CredentialsInfoEndpointClient(
                    rsspMetadata.rsspId.value.value,
                    ktorHttpClientFactory,
                )

            val authorizeCredentialImpl = AuthorizeCredentialImpl(
                authorizationEndpointClient,
                tokenEndpointClient,
                credentialsInfoEndpointClient,
            )

            val credentialsListEndpointClient =
                CredentialsListEndpointClient(
                    rsspMetadata.rsspId.value.value,
                    ktorHttpClientFactory,
                )

            val listCredentialsImpl = ListCredentials(credentialsListEndpointClient)

            val getCredentialInfoImpl = GetCredentialInfo(credentialsInfoEndpointClient)

            val signHashEndpointClient = SignHashEndpointClient(
                rsspMetadata.rsspId.value.value,
                ktorHttpClientFactory,
            )

            val signHashImpl = SignHashImpl(
                signHashEndpointClient,
            )

            val calculateDocumentHashesImpl = CalculateDocumentHashesImpl().also {
                CalculateDocumentHashesImpl.initialize(podofoManager, cscClientConfig.tsaurl)
            }

            val signDocImpl = SignDocImpl(
                signHashEndpointClient,
            )

            val embedSignatureImpl = CreateSignedDocumentsImpl().also {
                CreateSignedDocumentsImpl.initialize(podofoManager, cscClientConfig)
            }

            object :
                CSCClient,
                AuthorizeService by authorizeServiceImpl,
                AuthorizeCredential by authorizeCredentialImpl,
                ListCredentials by listCredentialsImpl,
                GetCredentialInfo by getCredentialInfoImpl,
                SignHash by signHashImpl,
                SignDoc by signDocImpl,
                CreateSignedDocuments by embedSignatureImpl,
                CalculateDocumentHashes by calculateDocumentHashesImpl {
                override val rsspMetadata: RSSPMetadata = rsspMetadata
            }
        }
    }
}

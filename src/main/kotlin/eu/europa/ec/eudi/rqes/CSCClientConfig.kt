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

import java.net.URI
import java.time.Clock
import java.util.Locale

typealias ClientId = String

sealed interface OAuth2Client : java.io.Serializable {

    /**
     * The client_id
     */
    val clientId: ClientId

    data class Public(override val clientId: ClientId) : OAuth2Client

    sealed interface Confidential : OAuth2Client {
        data class ClientSecretBasic(override val clientId: ClientId, val clientSecret: String) : Confidential
        data class ClientSecretPost(override val clientId: ClientId, val clientSecret: String) : Confidential
    }
}

enum class ParUsage {
    IfSupported,
    Never,
    Required,
}

enum class RarUsage {
    IfSupported,
    Never,
    Required,
}

data class CSCClientConfig(
    val client: OAuth2Client,
    val authFlowRedirectionURI: URI,
    val parUsage: ParUsage = ParUsage.IfSupported,
    val rarUsage: RarUsage = RarUsage.IfSupported,
    val clock: Clock = Clock.systemDefaultZone(),
    val locale: Locale? = null,
    val tsaurl: String? = "",
    val includeRevocationInfo: Boolean = false,
)

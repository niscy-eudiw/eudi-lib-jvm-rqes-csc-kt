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
package eu.europa.ec.eudi.documentretrieval

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.oauth2.sdk.id.Issuer
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration

sealed interface JwkSetSource {
    data class ByValue(val jwks: JsonObject) : JwkSetSource
    data class ByReference(val jwksUri: URI) : JwkSetSource
}

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdScheme.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param legalName the name of the trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is uses to sign his request and a [way][JwkSetSource] to get his public key
 *
 */
data class PreregisteredClient(
    val clientId: String,
    val legalName: String,
    val jarConfig: Pair<JWSAlgorithm, JwkSetSource>? = null,
)

fun interface X509CertificateTrust {
    fun isTrusted(chain: List<X509Certificate>): Boolean
}

/**
 * The Client identifier scheme supported (or trusted) by the wallet.
 */
sealed interface SupportedClientIdScheme {

    /**
     * The Client Identifier is known to the Wallet in advance of the Authorization Request.
     */
    data class Preregistered(val clients: Map<String, PreregisteredClient>) : SupportedClientIdScheme {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a URI and
     * match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanUri(val trust: X509CertificateTrust) : SupportedClientIdScheme {
        companion object {
            internal val NoValidation: X509SanUri = X509SanUri { _ -> true }
        }
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this scheme, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val trust: X509CertificateTrust) : SupportedClientIdScheme {
        companion object {
            internal val NoValidation: X509SanDns = X509SanDns { _ -> true }
        }
    }

    fun scheme(): ClientIdScheme = when (this) {
        is Preregistered -> ClientIdScheme.PreRegistered
        is X509SanDns -> ClientIdScheme.X509_SAN_DNS
        is X509SanUri -> ClientIdScheme.X509_SAN_URI
    }
}

data class DocumentRetrievalConfig(
    val jarConfiguration: JarConfiguration = JarConfiguration.Default,
    val clock: Clock = Clock.systemDefaultZone(),
    val jarClockSkew: Duration = Duration.ofSeconds(15L),
    val supportedClientIdSchemes: List<SupportedClientIdScheme>,
) {
    init {
        require(supportedClientIdSchemes.isNotEmpty()) { "At least a supported client id scheme must be provided" }
    }

    constructor(
        issuer: Issuer? = SelfIssued,
        jarConfiguration: JarConfiguration = JarConfiguration.Default,
        clock: Clock = Clock.systemDefaultZone(),
        jarClockSkew: Duration = Duration.ofSeconds(15L),
        vararg supportedClientIdSchemes: SupportedClientIdScheme,
    ) : this(
        jarConfiguration,
        clock,
        jarClockSkew,
        supportedClientIdSchemes.toList(),
    )

    companion object {
        /**
         * Identifies the wallet as `https://self-issued.me/v2`
         */
        val SelfIssued = Issuer(URI.create("https://self-issued.me/v2"))
    }
}

/**
 * Options related to JWT-Secured authorization requests
 *
 * @param supportedAlgorithms the algorithms supported for the signature of the JAR
 */
data class JarConfiguration(
    val supportedAlgorithms: List<JWSAlgorithm>,
) {
    init {
        require(supportedAlgorithms.isNotEmpty()) { "JAR signing algorithms cannot be empty" }
    }

    companion object {
        /**
         * The default JAR configuration list as trusted algorithms ES256, ES384, and ES512.
         */
        val Default = JarConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512),
        )
    }
}

internal fun DocumentRetrievalConfig.supportedClientIdScheme(scheme: ClientIdScheme): SupportedClientIdScheme? =
    supportedClientIdSchemes.firstOrNull { it.scheme() == scheme }

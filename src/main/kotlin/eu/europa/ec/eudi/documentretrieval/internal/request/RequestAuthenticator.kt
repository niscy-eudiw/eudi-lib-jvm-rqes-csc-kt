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
package eu.europa.ec.eudi.documentretrieval.internal.request

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.*
import com.nimbusds.jose.shaded.gson.Gson
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.util.DateUtils
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.documentretrieval.internal.sanOfDNSName
import eu.europa.ec.eudi.documentretrieval.internal.sanOfUniformResourceIdentifier
import eu.europa.ec.eudi.rqes.internal.ensure
import eu.europa.ec.eudi.rqes.internal.ensureNotNull
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import java.net.URI
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import kotlin.time.Duration
import kotlin.time.toKotlinDuration

internal sealed interface AuthenticatedClient {
    data class Preregistered(val preregisteredClient: PreregisteredClient) : AuthenticatedClient
    data class X509SanDns(val clientId: String, val chain: List<X509Certificate>) : AuthenticatedClient
    data class X509SanUri(val clientId: URI, val chain: List<X509Certificate>) : AuthenticatedClient
}

internal data class AuthenticatedRequest(
    val client: AuthenticatedClient,
    val requestObject: UnvalidatedRequestObject,
)

internal class RequestAuthenticator(documentRetrievalConfig: DocumentRetrievalConfig, httpClient: HttpClient) {
    private val clientAuthenticator = ClientAuthenticator(documentRetrievalConfig)
    private val signatureVerifier = JarJwtSignatureVerifier(documentRetrievalConfig, httpClient)

    suspend fun authenticate(request: FetchedRequest): AuthenticatedRequest = coroutineScope {
        val client = clientAuthenticator.authenticateClient(request)
        with(signatureVerifier) { verifySignature(client, request.jwt) }
        AuthenticatedRequest(client, request.jwt.requestObject())
    }
}

internal class ClientAuthenticator(private val documentRetrievalConfig: DocumentRetrievalConfig) {
    fun authenticateClient(request: FetchedRequest): AuthenticatedClient {
        val requestObject = request.jwt.requestObject()

        val (clientId, clientIdScheme) = clientIdAndScheme(requestObject)
        return when (clientIdScheme) {
            is SupportedClientIdScheme.Preregistered -> {
                val registeredClient = clientIdScheme.clients[clientId]
                ensureNotNull(registeredClient) { RequestValidationError.InvalidClientId.asException() }
                ensureNotNull(registeredClient.jarConfig) {
                    invalidScheme("$registeredClient cannot place signed request")
                }

                AuthenticatedClient.Preregistered(registeredClient)
            }

            is SupportedClientIdScheme.X509SanDns -> {
                val chain = x5c(request, clientIdScheme.trust) {
                    val dnsNames = sanOfDNSName().getOrNull()
                    ensureNotNull(dnsNames) { invalidJarJwt("Certificates misses DNS names") }
                }
                AuthenticatedClient.X509SanDns(request.clientId, chain)
            }

            is SupportedClientIdScheme.X509SanUri -> {
                val chain = x5c(request, clientIdScheme.trust) {
                    val dnsNames = sanOfUniformResourceIdentifier().getOrNull()
                    ensureNotNull(dnsNames) { invalidJarJwt("Certificates misses URI names") }
                }
                val clientIdUri = clientId.asURI { RequestValidationError.InvalidClientId.asException() }.getOrThrow()
                AuthenticatedClient.X509SanUri(clientIdUri, chain)
            }
        }
    }

    private fun clientIdAndScheme(requestObject: UnvalidatedRequestObject): Pair<String, SupportedClientIdScheme> {
        val clientId = ensureNotNull(requestObject.clientId) { RequestValidationError.MissingClientId.asException() }
        val clientIdScheme = requestObject.clientIdScheme?.let { ClientIdScheme.make(it) } ?: ClientIdScheme.PreRegistered
        ensureNotNull(clientIdScheme) { invalidScheme("Missing or invalid client_id_scheme") }
        val supportedClientIdScheme = documentRetrievalConfig.supportedClientIdScheme(clientIdScheme)
        ensureNotNull(supportedClientIdScheme) { RequestValidationError.UnsupportedClientIdScheme.asException() }
        return clientId to supportedClientIdScheme
    }

    private fun x5c(
        request: FetchedRequest,
        trust: X509CertificateTrust,
        subjectAlternativeNames: X509Certificate.() -> List<String>,
    ): List<X509Certificate> {
        val x5c = request.jwt.header?.x509CertChain
        ensureNotNull(x5c) { invalidJarJwt("Missing x5c") }
        val pubCertChain = x5c.mapNotNull { runCatching { X509CertUtils.parse(it.decode()) }.getOrNull() }
        ensure(pubCertChain.isNotEmpty()) { invalidJarJwt("Invalid x5c") }

        val alternativeNames = pubCertChain[0].subjectAlternativeNames()
        ensure(request.clientId in alternativeNames) {
            invalidJarJwt("ClientId not found in certificate's subject alternative names")
        }
        ensure(trust.isTrusted(pubCertChain)) { invalidJarJwt("Untrusted x5c") }
        return pubCertChain
    }
}

/**
 * Validates a JWT that represents an Authorization Request according to RFC9101
 *
 * @param documentRetrievalConfig wallet's configuration
 */
private class JarJwtSignatureVerifier(
    private val documentRetrievalConfig: DocumentRetrievalConfig,
    private val httpClient: HttpClient,
) {

    @Throws(AuthorizationRequestException::class)
    suspend fun verifySignature(client: AuthenticatedClient, signedJwt: SignedJWT) {
        try {
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                // see also: DefaultJOSEObjectTypeVerifier.JWT
                jwsTypeVerifier =
                    DefaultJOSEObjectTypeVerifier(
                        JOSEObjectType("oauth-authz-req+jwt"),
                        JOSEObjectType.JWT,
                        JOSEObjectType(""),
                        null,
                    )
                jwsKeySelector = jwsKeySelector(client)
                jwtClaimsSetVerifier =
                    TimeChecks(documentRetrievalConfig.clock, documentRetrievalConfig.jarClockSkew.toKotlinDuration())
            }
            jwtProcessor.process(signedJwt, null)
        } catch (e: JOSEException) {
            throw RuntimeException(e)
        } catch (e: BadJOSEException) {
            throw invalidJarJwt("Invalid signature ${e.message}")
        }
    }

    @Throws(AuthorizationRequestException::class)
    private suspend fun jwsKeySelector(client: AuthenticatedClient): JWSKeySelector<SecurityContext> =
        when (client) {
            is AuthenticatedClient.Preregistered ->
                getPreRegisteredClientJwsSelector(client)

            is AuthenticatedClient.X509SanUri ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }

            is AuthenticatedClient.X509SanDns ->
                JWSKeySelector<SecurityContext> { _, _ -> listOf(client.chain[0].publicKey) }
        }

    @Throws(AuthorizationRequestException::class)
    private suspend fun getPreRegisteredClientJwsSelector(
        preregistered: AuthenticatedClient.Preregistered,
    ): JWSVerificationKeySelector<SecurityContext> {
        val trustedClient = preregistered.preregisteredClient
        val jarConfig = checkNotNull(trustedClient.jarConfig)

        val (jarSigningAlg, jwkSetSource) = jarConfig
        suspend fun getJWKSource(): JWKSource<SecurityContext> {
            val jwkSet = when (jwkSetSource) {
                is JwkSetSource.ByValue -> JWKSet.parse(jwkSetSource.jwks.toString())
                is JwkSetSource.ByReference -> {
                    val unparsed = httpClient.get(jwkSetSource.jwksUri.toURL()).body<String>()
                    JWKSet.parse(unparsed)
                }
            }
            return ImmutableJWKSet(jwkSet)
        }

        val jwkSource = getJWKSource()
        return JWSVerificationKeySelector(jarSigningAlg, jwkSource)
    }
}

private fun invalidScheme(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidClientIdScheme(cause).asException()

private fun invalidJarJwt(cause: String): AuthorizationRequestException =
    RequestValidationError.InvalidJarJwt(cause).asException()

private fun SignedJWT.requestObject(): UnvalidatedRequestObject {
    fun List<Any?>.asJsonArray(): JsonArray {
        return Json.parseToJsonElement(Gson().toJson(this)).jsonArray
    }

    return with(jwtClaimsSet) {
        UnvalidatedRequestObject(
            responseType = getStringClaim("response_type"),
            clientId = getStringClaim("client_id"),
            clientIdScheme = getStringClaim("client_id_scheme"),
            responseMode = getStringClaim("response_mode"),
            responseUri = getStringClaim("response_uri"),
            nonce = getStringClaim("nonce"),
            state = getStringClaim("state"),
            signatureQualifier = getStringClaim("signatureQualifier"),
            documentDigests = getListClaim("documentDigests").asJsonArray(),
            documentLocations = getListClaim("documentLocations").asJsonArray(),
            hashAlgorithmOID = getStringClaim("hashAlgorithmOID"),
            clientData = getStringClaim("clientData"),
        )
    }
}

private class TimeChecks(
    private val clock: Clock,
    private val skew: Duration,
) : JWTClaimsSetVerifier<SecurityContext> {

    @Throws(BadJWTException::class)
    override fun verify(claimsSet: JWTClaimsSet, context: SecurityContext?) {
        val now = Date.from(clock.instant())
        val skewInSeconds = skew.inWholeSeconds

        val exp = claimsSet.expirationTime
        if (exp != null && !DateUtils.isAfter(exp, now, skewInSeconds)) {
            throw BadJWTException("Expired JWT")
        }

        val nbf = claimsSet.notBeforeTime
        if (nbf != null && !DateUtils.isBefore(nbf, now, skewInSeconds)) {
            throw BadJWTException("JWT before use time")
        }
    }
}

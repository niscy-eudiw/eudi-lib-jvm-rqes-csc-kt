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
package eu.europa.ec.eudi.documentretrieval

import java.io.Serializable
import java.net.URI

/**
 * This interface assembles an appropriate authorization response given a [request][ResolvedRequestObject]
 * and holder's [consensus][Consensus] and then dispatches it to the verifier
 */
fun interface Dispatcher {

    /**
     * Assembles an appropriate authorization response given a [request][request]
     * and holder's [consensus][Consensus] and then dispatches it to the verifier.
     */
    suspend fun dispatch(
        request: ResolvedRequestObject,
        consensus: Consensus,
    ): DispatchOutcome
}

/**
 * Representation of holder's consensus to
 * a [ResolvedRequestObject]
 */
sealed interface Consensus : Serializable {

    /**
     * Positive consensus. Holder decided to
     *  respond to the request
     */
    data class Positive(
        val documentWithSignature: List<String>?,
        val signatureObject: List<String>?,
    ) : Consensus {
        init {
            require(documentWithSignature != null || signatureObject != null) {
                "At least one of documentWithSignature or signatureObject must be present"
            }
        }
    }

    /**
     * No consensus. Holder decided to reject
     * the request
     */
    data class Negative(val error: String) : Consensus
}

/**
 * The outcome of dispatching an [Consensus] to
 * verifier/RP.
 */
sealed interface DispatchOutcome : Serializable {

    /**
     * When verifier/RP acknowledged the direct post
     */
    data class Accepted(val redirectURI: URI?) : DispatchOutcome

    /**
     * When verifier/RP reject the direct post
     */
    data object Rejected : DispatchOutcome {
        private fun readResolve(): Any = Rejected
    }
}

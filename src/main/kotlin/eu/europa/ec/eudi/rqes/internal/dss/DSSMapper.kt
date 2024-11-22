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
package eu.europa.ec.eudi.rqes.internal.dss

import eu.europa.ec.eudi.rqes.ASiCContainer
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.SignedEnvelopeProperty
import eu.europa.esig.dss.enumerations.ASiCContainerType
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.enumerations.SignaturePackaging

internal fun mapToDSSASiCContainer(asicContainer: ASiCContainer) =
    asicContainer.toDss() ?:  throw IllegalArgumentException("Unsupported ASiC container type: $asicContainer")

internal fun ASiCContainer.toDss(): ASiCContainerType? = when(this) {
    ASiCContainer.NONE -> null
    ASiCContainer.ASIC_E -> ASiCContainerType.ASiC_E
    ASiCContainer.ASIC_S -> ASiCContainerType.ASiC_S
}

internal fun mapToDSSSignaturePackaging(signedEnvelopeProperty: SignedEnvelopeProperty) =
    when (signedEnvelopeProperty) {
        SignedEnvelopeProperty.ENVELOPED -> SignaturePackaging.ENVELOPED
        SignedEnvelopeProperty.ENVELOPING -> SignaturePackaging.ENVELOPING
        SignedEnvelopeProperty.DETACHED -> SignaturePackaging.DETACHED
        SignedEnvelopeProperty.INTERNALLY_DETACHED -> SignaturePackaging.INTERNALLY_DETACHED
    }

internal fun mapToDSSDigestAlgorithm(hashAlgorithmOID: HashAlgorithmOID): DigestAlgorithm =
    try {
        DigestAlgorithm.forOID(hashAlgorithmOID.value)
    } catch (e: IllegalArgumentException) {
        try {
            val signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.forOID(hashAlgorithmOID.value)
            signatureAlgorithm.digestAlgorithm
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Unsupported hash algorithm OID: $hashAlgorithmOID")
        }
    }

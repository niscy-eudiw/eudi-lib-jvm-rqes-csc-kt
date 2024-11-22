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
import kotlin.test.Test
import kotlin.test.assertEquals

class ListCredentialsTest {

    @Test
    fun `successful retrieval of credentials list`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsListPostMocker(),
        )

        val credentialsList = with(mockPublicClient(mockedKtorHttpClientFactory)) {
            with(mockServiceAccessAuthorized) {
                listCredentials(CredentialsListRequest()).getOrThrow()
            }
        }

        assertEquals(1, credentialsList.size)
        assertEquals("83c7c559-db74-48da-aacc-d439d415cb81", credentialsList[0].credentialID.value)
    }
}

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

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

interface RevocationService {
    suspend fun getCrlData(request: CrlRequest): CrlResponse
}

class RevocationServiceImpl : RevocationService {

    override suspend fun getCrlData(request: CrlRequest): CrlResponse {
        return try {
            val crlData = makeRequest(request.crlUrl)
            val base64Crl = Base64.getEncoder().encodeToString(crlData)
            CrlResponse(crlInfoBase64 = base64Crl)
        } catch (e: Exception) {
            throw RuntimeException("Failed to get CRL data", e)
        }
    }

    private fun makeRequest(crlUrl: String): ByteArray {
        val url = try {
            URL(crlUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid CRL URL", e)
        }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 5000
            readTimeout = 5000
        }

        val responseCode = connection.responseCode
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw IOException("CRL server responded with HTTP $responseCode")
        }

        return connection.inputStream.use { it.readBytes() }
    }
}

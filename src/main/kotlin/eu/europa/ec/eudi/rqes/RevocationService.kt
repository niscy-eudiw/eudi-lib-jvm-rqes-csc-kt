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

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

interface RevocationService {
    suspend fun getCrlData(request: CrlRequest): CrlResponse
    suspend fun getOcspData(request: OcspRequest): OcspResponse
    suspend fun getCertificateData(request: CertificateRequest): CertificateResponse
}

class RevocationServiceImpl : RevocationService {

    override suspend fun getCrlData(request: CrlRequest): CrlResponse {
        return try {
            val crlData = makeCrlRequest(request.crlUrl)
            val base64Crl = Base64.getEncoder().encodeToString(crlData)
            CrlResponse(crlInfoBase64 = base64Crl)
        } catch (e: Exception) {
            throw RuntimeException("Failed to get CRL data", e)
        }
    }

    override suspend fun getOcspData(request: OcspRequest): OcspResponse {
        return try {
            val ocspData = makeOcspRequest(request)
            val base64Ocsp = Base64.getEncoder().encodeToString(ocspData)
            OcspResponse(ocspInfoBase64 = base64Ocsp)
        } catch (e: Exception) {
            throw RuntimeException("Failed to get OCSP data", e)
        }
    }

    override suspend fun getCertificateData(request: CertificateRequest): CertificateResponse {
        return try {
            val certificateData = makeCertificateRequest(request.certificateUrl)
            val base64Certificate = Base64.getEncoder().encodeToString(certificateData)
            CertificateResponse(certificateBase64 = base64Certificate)
        } catch (e: Exception) {
            throw RuntimeException("Failed to get certificate data", e)
        }
    }

    private fun makeCrlRequest(crlUrl: String): ByteArray {
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

    private fun makeOcspRequest(request: OcspRequest): ByteArray {
        val url = try {
            URL(request.ocspUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid OCSP URL", e)
        }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/ocsp-request")
            connectTimeout = 5000
            readTimeout = 5000
            doOutput = true
        }

        val postData = Base64.getDecoder().decode(request.ocspRequest)
        connection.outputStream.use { it.write(postData) }

        val responseCode = connection.responseCode
        if (responseCode !in 200..299) {
            throw IOException("OCSP server responded with HTTP $responseCode")
        }

        return connection.inputStream.use { it.readBytes() }
    }

    private fun makeCertificateRequest(certificateUrl: String): ByteArray {
        val url = try {
            URL(certificateUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid certificate URL", e)
        }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 5000
            readTimeout = 5000
        }

        val responseCode = connection.responseCode
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw IOException("Certificate server responded with HTTP $responseCode")
        }

        return connection.inputStream.use { it.readBytes() }
    }
}

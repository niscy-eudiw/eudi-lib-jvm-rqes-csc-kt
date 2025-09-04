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

import java.security.MessageDigest
import java.util.Base64
import java.net.URL
import java.io.IOException
import java.net.HttpURLConnection

class TimestampServiceImpl {

    suspend fun requestTimestamp(request: TimestampRequestTO): TimestampResponseTO {
        val tsq = buildTSQ(request.signedHash)
        return getTimestampResponse(tsq, request.tsaUrl)
    }

    suspend fun requestDocTimestamp(request: TimestampRequestTO): TimestampResponseTO {
        val tsq = buildTSQForDocTimestamp(request.signedHash)
        return getTimestampResponse(tsq, request.tsaUrl)
    }

    private suspend fun getTimestampResponse(tsq: ByteArray, tsaUrl: String): TimestampResponseTO {
        return try {
            val tsrData = makeRequest(tsq, tsaUrl)
            val base64Tsr = encodeTSRToBase64(tsrData)
            TimestampResponseTO(base64Tsr = base64Tsr)
        } catch (e: Exception) {
            throw RuntimeException("Failed to generate timestamp", e)
        }
    }

    private fun buildTSQ(signedHashBase64: String): ByteArray {
        require (signedHashBase64.isNotBlank()) {"Empty signed hash"}

        val rawHash = try {
            Base64.getDecoder().decode(signedHashBase64)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Base64", e)
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(rawHash)

        return createTSQ(digest)
    }

    private fun buildTSQForDocTimestamp(rawHashBase64: String): ByteArray {
        require (rawHashBase64.isNotBlank()) {
            "Empty hash"
        }

        val digestData = try {
            Base64.getDecoder().decode(rawHashBase64)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Base64", e)
        }

        return createTSQ(digestData)
    }

    private fun createTSQ(digestData: ByteArray): ByteArray {
        val oidSHA256 = byteArrayOf(
            0x06, 0x09, 0x60.toByte(), 0x86.toByte(), 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x01
        )
        val nullBytes = byteArrayOf(0x05, 0x00)
        val algIDSeq = tlv(0x30, oidSHA256 + nullBytes)

        val octetDigest = tlv(0x04, digestData)
        val msgImprintSeq = tlv(0x30, algIDSeq + octetDigest)

        val versionBytes = byteArrayOf(0x02, 0x01, 0x01)
        val certReqBytes = byteArrayOf(0x01, 0x01, 0xFF.toByte())

        val tsReqBody = versionBytes + msgImprintSeq + certReqBytes
        val tsq = tlv(0x30, tsReqBody)
        return tsq
    }

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val lengthBytes = encodeLength(value.size)
        return byteArrayOf(tag.toByte()) + lengthBytes + value
    }

    private fun encodeLength(length: Int): ByteArray {
        return if (length < 0x80) {
            byteArrayOf(length.toByte())
        } else {
            val tmp = mutableListOf<Byte>()
            var len = length
            while (len > 0) {
                tmp.add(0, (len and 0xFF).toByte())
                len = len shr 8
            }
            byteArrayOf((0x80 or tmp.size).toByte()) + tmp.toByteArray()
        }
    }

    private fun makeRequest(tsqData: ByteArray, tsaUrl: String): ByteArray {
        val url = try {
            URL(tsaUrl)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid TSA URL", e)
        }

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            doInput = true
            connectTimeout = 5000
            readTimeout = 5000
            setRequestProperty("Content-Type", "application/timestamp-query")
            setRequestProperty("Accept", "application/timestamp-reply")
        }

        connection.outputStream.use { it.write(tsqData) }

        val responseCode = connection.responseCode
        if (responseCode != 200) {
            throw IOException("TSA server responded with HTTP $responseCode")
        }

        val responseData = connection.inputStream.use { it.readBytes() }
        return responseData
    }

    private fun encodeTSRToBase64(tsrData: ByteArray): String {
        return Base64.getEncoder().encodeToString(tsrData)
    }
}


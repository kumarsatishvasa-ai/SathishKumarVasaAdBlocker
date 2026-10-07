package com.sathishkumarvasa.adblocker

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal DNS packet parser/builder.
 *
 * This implementation handles standard DNS queries and
 * creates simple NXDOMAIN / empty-answer responses for
 * blocked domains.
 */
object DnsPacket {

    data class Query(
        val transactionId: Int,
        val flags: Int,
        val questionEnd: Int,
        val hostname: String,
        val questionBytes: ByteArray
    )

    fun parseQuery(
        packet: ByteArray,
        length: Int = packet.size
    ): Query? {

        if (length < 12) {
            return null
        }

        val data =
            packet.copyOf(length)

        val buffer =
            ByteBuffer
                .wrap(data)
                .order(
                    ByteOrder.BIG_ENDIAN
                )

        val transactionId =
            buffer.short
                .toInt() and 0xFFFF

        val flags =
            buffer.short
                .toInt() and 0xFFFF

        val questionCount =
            buffer.short
                .toInt() and 0xFFFF

        val answerCount =
            buffer.short
                .toInt() and 0xFFFF

        val authorityCount =
            buffer.short
                .toInt() and 0xFFFF

        val additionalCount =
            buffer.short
                .toInt() and 0xFFFF

        /*
         * We only process standard one-question queries.
         */
        if (
            questionCount != 1
        ) {
            return null
        }

        var position =
            12

        val labels =
            ArrayList<String>()

        while (
            position < length
        ) {

            val size =
                data[position]
                    .toInt() and 0xFF

            position++

            if (size == 0) {
                break
            }

            /*
             * Compression pointer.
             *
             * Queries normally do not use one for QNAME,
             * so we reject it here.
             */
            if (
                size and 0xC0 == 0xC0
            ) {
                return null
            }

            if (
                size > 63 ||
                position + size > length
            ) {
                return null
            }

            labels.add(
                String(
                    data,
                    position,
                    size,
                    Charsets.US_ASCII
                )
            )

            position += size
        }

        /*
         * QNAME terminator must be present.
         */
        if (
            position >= length
        ) {
            return null
        }

        /*
         * QTYPE + QCLASS.
         */
        if (
            position + 4 > length
        ) {
            return null
        }

        position += 4

        val hostname =
            labels.joinToString(".")
                .lowercase()

        if (hostname.isEmpty()) {
            return null
        }

        val questionBytes =
            data.copyOfRange(
                12,
                position
            )

        return Query(
            transactionId =
                transactionId,

            flags =
                flags,

            questionEnd =
                position,

            hostname =
                hostname,

            questionBytes =
                questionBytes
        )
    }

    /**
     * Creates a DNS response containing no answers.
     *
     * For a blocked hostname we return NXDOMAIN.
     */
    fun buildBlockedResponse(
        query: Query
    ): ByteArray {

        val buffer =
            ByteBuffer
                .allocate(
                    12 +
                        query.questionBytes.size
                )
                .order(
                    ByteOrder.BIG_ENDIAN
                )

        buffer.putShort(
            query.transactionId
                .toShort()
        )

        /*
         * QR = response
         * RD = recursion desired copied from query
         * RA = recursion available
         * RCODE = NXDOMAIN (3)
         */
        var flags =
            0x8000

        flags =
            flags or
                (query.flags and 0x0100)

        flags =
            flags or 0x0080

        flags =
            flags or 0x0003

        buffer.putShort(
            flags.toShort()
        )

        /*
         * One question.
         */
        buffer.putShort(
            1.toShort()
        )

        /*
         * No answers.
         */
        buffer.putShort(
            0.toShort()
        )

        /*
         * No authority records.
         */
        buffer.putShort(
            0.toShort()
        )

        /*
         * No additional records.
         */
        buffer.putShort(
            0.toShort()
        )

        buffer.put(
            query.questionBytes
        )

        return buffer.array()
    }

    /**
     * Builds a simple A record response.
     *
     * This is useful for returning a local address for
     * allowed DNS queries when the upstream response is
     * already known.
     */
    fun buildAResponse(
        query: Query,
        address: ByteArray,
        ttl: Int = 60
    ): ByteArray {

        require(
            address.size == 4
        ) {
            "IPv4 address must contain 4 bytes."
        }

        val buffer =
            ByteBuffer
                .allocate(
                    12 +
                        query.questionBytes.size +
                        16
                )
                .order(
                    ByteOrder.BIG_ENDIAN
                )

        buffer.putShort(
            query.transactionId
                .toShort()
        )

        var flags =
            0x8000

        flags =
            flags or
                (query.flags and 0x0100)

        flags =
            flags or 0x0080

        buffer.putShort(
            flags.toShort()
        )

        buffer.putShort(
            1.toShort()
        )

        buffer.putShort(
            1.toShort()
        )

        buffer.putShort(
            0.toShort()
        )

        buffer.putShort(
            0.toShort()
        )

        buffer.put(
            query.questionBytes
        )

        /*
         * NAME = pointer to QNAME at offset 12.
         */
        buffer.putShort(
            0xC00C.toShort()
        )

        /*
         * TYPE = A.
         */
        buffer.putShort(
            1.toShort()
        )

        /*
         * CLASS = IN.
         */
        buffer.putShort(
            1.toShort()
        )

        buffer.putInt(
            ttl
        )

        /*
         * IPv4 address length.
         */
        buffer.putShort(
            4.toShort()
        )

        buffer.put(address)

        return buffer.array()
    }
}


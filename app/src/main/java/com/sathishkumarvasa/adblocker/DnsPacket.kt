package com.sathishkumarvasa.adblocker

object DnsPacket {

    data class DnsQuery(
        val transactionId: Int,
        val flags: Int,
        val hostname: String,
        val questionType: Int,
        val questionClass: Int
    )

    fun parseQuery(
        packet: ByteArray
    ): DnsQuery? {

        /*
         * DNS header:
         *
         * 0-1   transaction ID
         * 2-3   flags
         * 4-5   question count
         * 6-7   answer count
         * 8-9   authority count
         * 10-11 additional count
         */
        if (
            packet.size < DNS_HEADER_LENGTH
        ) {
            return null
        }

        val transactionId =
            readUnsignedShort(
                packet,
                0
            )

        val flags =
            readUnsignedShort(
                packet,
                2
            )

        /*
         * QR bit:
         *
         * 0 = query
         * 1 = response
         */
        if (
            flags and FLAG_RESPONSE != 0
        ) {
            return null
        }

        val questionCount =
            readUnsignedShort(
                packet,
                4
            )

        if (
            questionCount <= 0
        ) {
            return null
        }

        /*
         * We only inspect the first question.
         */
        var offset =
            DNS_HEADER_LENGTH

        val hostnameResult =
            readHostname(
                packet,
                offset
            )
                ?: return null

        val hostname =
            hostnameResult.first

        offset =
            hostnameResult.second

        /*
         * QTYPE + QCLASS.
         */
        if (
            offset + 4 > packet.size
        ) {
            return null
        }

        val questionType =
            readUnsignedShort(
                packet,
                offset
            )

        val questionClass =
            readUnsignedShort(
                packet,
                offset + 2
            )

        /*
         * Only standard Internet DNS questions are
         * currently handled.
         */
        if (
            questionClass != CLASS_IN
        ) {
            return null
        }

        if (
            hostname.isEmpty()
        ) {
            return null
        }

        return DnsQuery(
            transactionId =
                transactionId,

            flags =
                flags,

            hostname =
                hostname,

            questionType =
                questionType,

            questionClass =
                questionClass
        )
    }

    private fun readHostname(
        packet: ByteArray,
        startOffset: Int
    ): Pair<String, Int>? {

        var offset =
            startOffset

        val labels =
            ArrayList<String>()

        /*
         * DNS names are limited to 255 bytes.
         */
        var totalLength =
            0

        while (true) {

            if (
                offset >= packet.size
            ) {
                return null
            }

            val length =
                packet[offset].toInt() and 0xFF

            offset++

            /*
             * Zero marks the end of the QNAME.
             */
            if (
                length == 0
            ) {
                break
            }

            /*
             * Compression pointers should not appear
             * in a normal DNS question. Reject them to
             * avoid pointer-loop complexity.
             */
            if (
                length and 0xC0 == 0xC0
            ) {
                return null
            }

            /*
             * DNS labels are max 63 bytes.
             */
            if (
                length > 63
            ) {
                return null
            }

            if (
                offset + length >
                packet.size
            ) {
                return null
            }

            totalLength +=
                length + 1

            if (
                totalLength > 255
            ) {
                return null
            }

            val labelBytes =
                packet.copyOfRange(
                    offset,
                    offset + length
                )

            val label =
                try {

                    labelBytes
                        .toString(
                            Charsets.US_ASCII
                        )

                } catch (_: Exception) {

                    return null
                }

            if (
                label.isEmpty()
            ) {
                return null
            }

            /*
             * DNS hostnames used for filtering should
             * contain printable ASCII characters.
             */
            if (
                label.any {
                    it.code < 33 ||
                        it.code > 126
                }
            ) {
                return null
            }

            labels.add(
                label
            )

            offset +=
                length
        }

        if (
            labels.isEmpty()
        ) {
            return null
        }

        val hostname =
            labels.joinToString(
                "."
            )
                .lowercase()

        return hostname to offset
    }

    fun buildBlockedResponse(
        query: DnsQuery
    ): ByteArray {

        /*
         * Return an NXDOMAIN response.
         *
         * This tells the requesting application that
         * the domain does not exist.
         */
        val response =
            ByteArray(
                DNS_HEADER_LENGTH
            )

        /*
         * Transaction ID.
         */
        writeUnsignedShort(
            response,
            0,
            query.transactionId
        )

        /*
         * Flags:
         *
         * QR       = 1 response
         * AA       = 1 authoritative
         * RCODE    = 3 NXDOMAIN
         *
         * 0x8403
         */
        val flags =
            FLAG_RESPONSE or
                FLAG_AUTHORITATIVE or
                RCODE_NXDOMAIN

        writeUnsignedShort(
            response,
            2,
            flags
        )

        /*
         * QDCOUNT = 1
         */
        writeUnsignedShort(
            response,
            4,
            1
        )

        /*
         * No answers.
         */
        writeUnsignedShort(
            response,
            6,
            0
        )

        /*
         * No authority records.
         */
        writeUnsignedShort(
            response,
            8,
            0
        )

        /*
         * No additional records.
         */
        writeUnsignedShort(
            response,
            10,
            0
        )

        return response
    }

    private fun readUnsignedShort(
        data: ByteArray,
        offset: Int
    ): Int {

        if (
            offset < 0 ||
            offset + 1 >= data.size
        ) {
            return 0
        }

        return (
            ((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)
            )
    }

    private fun writeUnsignedShort(
        data: ByteArray,
        offset: Int,
        value: Int
    ) {

        if (
            offset < 0 ||
            offset + 1 >= data.size
        ) {
            return
        }

        data[offset] =
            (
                (value ushr 8) and 0xFF
                ).toByte()

        data[offset + 1] =
            (
                value and 0xFF
                ).toByte()
    }

    private const val DNS_HEADER_LENGTH =
        12

    private const val CLASS_IN =
        1

    private const val FLAG_RESPONSE =
        0x8000

    private const val FLAG_AUTHORITATIVE =
        0x0400

    private const val RCODE_NXDOMAIN =
        3
}

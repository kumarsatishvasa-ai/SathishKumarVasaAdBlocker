package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockVpnService : VpnService() {

    companion object {

        const val ACTION_START =
            "com.sathishkumarvasa.adblocker.START"

        const val ACTION_STOP =
            "com.sathishkumarvasa.adblocker.STOP"

        private const val TAG =
            "AdBlockVpnService"

        private const val CHANNEL_ID =
            "ad_blocker_vpn"

        private const val NOTIFICATION_ID =
            1001

        /*
         * Private address used by the VPN interface.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        /*
         * DNS server exposed to Android applications.
         *
         * Applications send DNS queries to this address
         * through the VPN interface.
         */
        private const val DNS_ADDRESS =
            "10.8.0.1"

        private const val DNS_PORT =
            53

        /*
         * Upstream DNS server.
         *
         * The socket is protected with VpnService.protect()
         * so it does NOT come back through this VPN.
         */
        private const val UPSTREAM_DNS =
            "1.1.1.1"

        private const val MTU =
            1500

        private const val MAX_PACKET_SIZE =
            32767

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val DNS_TIMEOUT_MS =
            4000

        private const val IPV4_HEADER_LENGTH =
            20

        private const val UDP_HEADER_LENGTH =
            8

        private const val DNS_HEADER_LENGTH =
            12

        private const val UDP_PROTOCOL =
            17

        private const val FILTER_REFRESH_MS =
            12L * 60L * 60L * 1000L

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    private var inputStream: FileInputStream? = null

    private var outputStream: FileOutputStream? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )

    private var packetJob: Job? = null

    private var filterJob: Job? = null

    private val running =
        AtomicBoolean(false)

    @Volatile
    private var dnsQueryCount = 0

    @Volatile
    private var blockedDnsCount = 0

    @Volatile
    private var forwardedDnsCount = 0

    // ============================================================
    // SERVICE
    // ============================================================

    override fun onCreate() {
        super.onCreate()

        createNotificationChannel()
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        when (intent?.action) {

            ACTION_STOP -> {
                stopVpn()
            }

            ACTION_START -> {
                startVpn()
            }

            else -> {
                startVpn()
            }
        }

        return START_STICKY
    }

    // ============================================================
    // START VPN
    // ============================================================

    private fun startVpn() {

        if (running.get()) {
            return
        }

        dnsQueryCount = 0
        blockedDnsCount = 0
        forwardedDnsCount = 0

        try {

            startForeground(
                NOTIFICATION_ID,
                createNotification(
                    "Starting DNS protection..."
                )
            )

            /*
             * IMPORTANT:
             *
             * This is a DNS-only VPN.
             *
             * We DO NOT use:
             *
             * addRoute("0.0.0.0", 0)
             *
             * because that would send normal Chrome,
             * YouTube, HTTPS, QUIC, etc. traffic into
             * this service.
             *
             * This service only processes DNS packets.
             */
            val builder =
                Builder()
                    .setSession(
                        "DNS Ad Blocker"
                    )
                    .setMtu(MTU)

                    /*
                     * VPN interface address.
                     */
                    .addAddress(
                        VPN_ADDRESS,
                        VPN_PREFIX
                    )

                    /*
                     * Tell Android that our VPN DNS
                     * server is 10.8.0.1.
                     */
                    .addDnsServer(
                        DNS_ADDRESS
                    )

                    /*
                     * Only route the VPN DNS address
                     * into our TUN interface.
                     */
                    .addRoute(
                        DNS_ADDRESS,
                        32
                    )

                    /*
                     * VERY IMPORTANT:
                     *
                     * Do not capture IPv6 traffic.
                     *
                     * Chrome and YouTube can use IPv6.
                     * Allowing IPv6 to fall through to the
                     * normal network prevents the VPN from
                     * accidentally breaking IPv6 connectivity.
                     */
                    .allowFamily(
                        OsConstants.AF_INET6
                    )

            /*
             * Do not route our own application into
             * its own VPN.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (e: Exception) {

                android.util.Log.w(
                    TAG,
                    "Could not exclude own application",
                    e
                )
            }

            val established =
                builder.establish()

            if (established == null) {

                android.util.Log.e(
                    TAG,
                    "VPN establish() returned null"
                )

                updateNotification(
                    "VPN could not be established"
                )

                stopVpn()

                return
            }

            vpnInterface =
                established

            inputStream =
                FileInputStream(
                    established.fileDescriptor
                )

            outputStream =
                FileOutputStream(
                    established.fileDescriptor
                )

            running.set(true)

            isRunning = true

            updateDiagnosticNotification()

            startPacketLoop()

            startFilterRefresh()

            android.util.Log.i(
                TAG,
                "DNS VPN started"
            )

        } catch (e: Exception) {

            android.util.Log.e(
                TAG,
                "Failed to start VPN",
                e
            )

            updateNotification(
                "VPN error: ${e.message ?: "unknown"}"
            )

            stopVpn()
        }
    }

    // ============================================================
    // PACKET LOOP
    // ============================================================

    private fun startPacketLoop() {

        packetJob?.cancel()

        packetJob =
            serviceScope.launch {

                val buffer =
                    ByteArray(
                        MAX_PACKET_SIZE
                    )

                while (
                    isActive &&
                    running.get()
                ) {

                    val input =
                        inputStream
                            ?: break

                    try {

                        val length =
                            input.read(buffer)

                        if (length <= 0) {
                            continue
                        }

                        processPacket(
                            buffer,
                            length
                        )

                    } catch (e: Exception) {

                        if (running.get()) {

                            android.util.Log.w(
                                TAG,
                                "VPN packet read failed",
                                e
                            )
                        }

                        break
                    }
                }
            }
    }

    // ============================================================
    // IP PACKET
    // ============================================================

    private fun processPacket(
        buffer: ByteArray,
        packetLength: Int
    ) {

        /*
         * We only understand IPv4 here.
         *
         * IPv6 is intentionally allowed to bypass
         * this VPN.
         */
        if (
            packetLength < IPV4_HEADER_LENGTH
        ) {
            return
        }

        val version =
            (buffer[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        val headerLength =
            (buffer[0].toInt() and 0x0F) * 4

        if (
            headerLength < IPV4_HEADER_LENGTH ||
            headerLength > packetLength
        ) {
            return
        }

        val totalLength =
            readUnsignedShort(
                buffer,
                2
            )

        if (
            totalLength < headerLength ||
            totalLength > packetLength
        ) {
            return
        }

        /*
         * Only UDP is handled.
         *
         * Because the VPN only routes DNS_ADDRESS,
         * normal TCP/HTTPS traffic should never arrive here.
         */
        val protocol =
            buffer[9].toInt() and 0xFF

        if (protocol != UDP_PROTOCOL) {
            return
        }

        processUdpPacket(
            buffer,
            totalLength,
            headerLength
        )
    }

    // ============================================================
    // UDP
    // ============================================================

    private fun processUdpPacket(
        packet: ByteArray,
        totalLength: Int,
        ipHeaderLength: Int
    ) {

        val udpOffset =
            ipHeaderLength

        if (
            totalLength <
            udpOffset + UDP_HEADER_LENGTH
        ) {
            return
        }

        val sourcePort =
            readUnsignedShort(
                packet,
                udpOffset
            )

        val destinationPort =
            readUnsignedShort(
                packet,
                udpOffset + 2
            )

        val udpLength =
            readUnsignedShort(
                packet,
                udpOffset + 4
            )

        if (
            udpLength < UDP_HEADER_LENGTH
        ) {
            return
        }

        if (
            udpOffset + udpLength >
            totalLength
        ) {
            return
        }

        /*
         * Only DNS destination port 53.
         */
        if (
            destinationPort != DNS_PORT
        ) {
            return
        }

        val dnsOffset =
            udpOffset +
                UDP_HEADER_LENGTH

        val dnsLength =
            udpLength -
                UDP_HEADER_LENGTH

        if (
            dnsLength < DNS_HEADER_LENGTH
        ) {
            return
        }

        if (
            dnsOffset + dnsLength >
            totalLength
        ) {
            return
        }

        val dnsQuery =
            packet.copyOfRange(
                dnsOffset,
                dnsOffset + dnsLength
            )

        handleDnsQuery(
            originalPacket = packet,
            originalLength = totalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsQuery = dnsQuery
        )
    }

    // ============================================================
    // DNS QUERY
    // ============================================================

    private fun handleDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        dnsQueryCount++

        /*
         * Safely extract the queried hostname.
         */
        val hostname =
            parseDnsQuestionName(
                dnsQuery
            )

        /*
         * If we cannot understand the DNS packet,
         * FAIL OPEN.
         *
         * This is deliberately chosen to protect
         * Chrome/YouTube connectivity.
         */
        if (hostname.isNullOrBlank()) {

            forwardedDnsCount++

            forwardDnsQuery(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsQuery
            )

            updateDiagnosticNotification()

            return
        }

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        android.util.Log.d(
            TAG,
            "DNS query: $normalized"
        )

        /*
         * Ask FilterManager ONLY about the hostname
         * that was actually queried.
         */
        val blocked =
            try {

                /*
                 * Allowlist is handled by FilterManager.
                 */
                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (e: Exception) {

                /*
                 * Filter problems must NEVER break
                 * Internet connectivity.
                 */
                android.util.Log.w(
                    TAG,
                    "Filter check failed for $normalized",
                    e
                )

                false
            }

        if (blocked) {

            blockedDnsCount++

            try {

                AdBlockStorage.incrementBlockedCount(
                    this
                )

            } catch (_: Exception) {
            }

            android.util.Log.d(
                TAG,
                "BLOCKED: $normalized"
            )

            val blockedResponse =
                buildBlockedDnsResponse(
                    dnsQuery
                )

            if (blockedResponse != null) {

                writeDnsResponse(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    destinationPort,
                    blockedResponse
                )

            } else {

                /*
                 * If we cannot construct a safe
                 * blocking response, fail open.
                 */
                forwardedDnsCount++

                forwardDnsQuery(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    destinationPort,
                    dnsQuery
                )
            }

        } else {

            forwardedDnsCount++

            android.util.Log.d(
                TAG,
                "ALLOWED: $normalized"
            )

            forwardDnsQuery(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsQuery
            )
        }

        updateDiagnosticNotification()
    }

    // ============================================================
    // DNS QUESTION PARSER
    // ============================================================

    private fun parseDnsQuestionName(
        dnsPacket: ByteArray
    ): String? {

        if (
            dnsPacket.size <
            DNS_HEADER_LENGTH + 5
        ) {
            return null
        }

        /*
         * QR bit.
         *
         * We only want client queries.
         *
         * QR = 0 => query
         * QR = 1 => response
         */
        val flags =
            readUnsignedShort(
                dnsPacket,
                2
            )

        if (
            flags and 0x8000 != 0
        ) {
            return null
        }

        val questionCount =
            readUnsignedShort(
                dnsPacket,
                4
            )

        if (
            questionCount <= 0
        ) {
            return null
        }

        var position =
            DNS_HEADER_LENGTH

        val labels =
            ArrayList<String>()

        while (
            position < dnsPacket.size
        ) {

            val length =
                dnsPacket[position]
                    .toInt() and 0xFF

            position++

            /*
             * End of hostname.
             */
            if (length == 0) {
                break
            }

            /*
             * Compression pointer is not expected
             * in a normal question name.
             */
            if (
                length and 0xC0 != 0
            ) {
                return null
            }

            if (
                length > 63
            ) {
                return null
            }

            if (
                position + length >
                dnsPacket.size
            ) {
                return null
            }

            val label =
                dnsPacket
                    .copyOfRange(
                        position,
                        position + length
                    )
                    .toString(
                        Charsets.US_ASCII
                    )

            if (label.isEmpty()) {
                return null
            }

            /*
             * Reject obviously invalid hostname characters.
             */
            for (character in label) {

                val valid =
                    character.isLetterOrDigit() ||
                        character == '-' ||
                        character == '_'

                if (!valid) {
                    return null
                }
            }

            labels.add(label)

            position += length

            if (labels.size > 127) {
                return null
            }
        }

        if (labels.isEmpty()) {
            return null
        }

        return labels
            .joinToString(".")
            .lowercase(Locale.US)
    }

    // ============================================================
    // BLOCKED DNS RESPONSE
    // ============================================================

    private fun buildBlockedDnsResponse(
        query: ByteArray
    ): ByteArray? {

        if (
            query.size <
            DNS_HEADER_LENGTH
        ) {
            return null
        }

        /*
         * We return the original DNS question
         * with an NXDOMAIN response.
         */
        val response =
            query.copyOf()

        val originalFlags =
            readUnsignedShort(
                query,
                2
            )

        /*
         * QR = 1
         */
        var flags =
            0x8000

        /*
         * Preserve RD.
         */
        if (
            originalFlags and 0x0100 != 0
        ) {
            flags =
                flags or 0x0100
        }

        /*
         * RA = 1
         */
        flags =
            flags or 0x0080

        /*
         * RCODE = 3 (NXDOMAIN)
         */
        flags =
            flags or 0x0003

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

    // ============================================================
    // FORWARD DNS
    // ============================================================

    private fun forwardDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        var socket: DatagramSocket? = null

        try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL.
             *
             * Without protect(), the socket could be routed
             * back through our VPN and create a DNS loop.
             */
            if (!protect(socket)) {

                android.util.Log.e(
                    TAG,
                    "Could not protect upstream DNS socket"
                )

                /*
                 * Fail silently rather than injecting
                 * a fake failure into the application.
                 */
                return
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    InetSocketAddress(
                        UPSTREAM_DNS,
                        DNS_PORT
                    )
                )

            socket.send(
                request
            )

            val responseBuffer =
                ByteArray(
                    MAX_DNS_PACKET_SIZE
                )

            val responsePacket =
                DatagramPacket(
                    responseBuffer,
                    responseBuffer.size
                )

            socket.receive(
                responsePacket
            )

            if (
                responsePacket.length <= 0
            ) {
                return
            }

            val response =
                responsePacket.data.copyOf(
                    responsePacket.length
                )

            /*
             * Verify DNS transaction ID.
             *
             * This prevents an unrelated response from
             * being delivered to the application.
             */
            if (
                dnsQuery.size >= 2 &&
                response.size >= 2
            ) {

                val queryId =
                    readUnsignedShort(
                        dnsQuery,
                        0
                    )

                val responseId =
                    readUnsignedShort(
                        response,
                        0
                    )

                if (
                    queryId != responseId
                ) {

                    android.util.Log.w(
                        TAG,
                        "DNS transaction ID mismatch"
                    )

                    return
                }
            }

            writeDnsResponse(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                response
            )

        } catch (e: Exception) {

            /*
             * DNS timeout/network failure.
             *
             * Do not crash the VPN.
             */
            android.util.Log.w(
                TAG,
                "Upstream DNS failed",
                e
            )

        } finally {

            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    // ============================================================
    // WRITE DNS RESPONSE
    // ============================================================

    private fun writeDnsResponse(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsResponse: ByteArray
    ) {

        val output =
            outputStream
                ?: return

        if (dnsResponse.isEmpty()) {
            return
        }

        /*
         * Keep the response within a reasonable
         * IPv4 UDP packet size for our MTU.
         *
         * If an upstream response is too large,
         * don't inject a malformed packet.
         */
        val maxDnsSize =
            MTU -
                IPV4_HEADER_LENGTH -
                UDP_HEADER_LENGTH

        if (
            dnsResponse.size > maxDnsSize
        ) {

            android.util.Log.w(
                TAG,
                "DNS response too large: ${dnsResponse.size}"
            )

            return
        }

        if (
            originalPacket.size <
            IPV4_HEADER_LENGTH
        ) {
            return
        }

        /*
         * Original:
         *
         * 10.8.0.2 -> 10.8.0.1
         *
         * Response:
         *
         * 10.8.0.1 -> 10.8.0.2
         */
        val originalSourceIp =
            originalPacket.copyOfRange(
                12,
                16
            )

        val originalDestinationIp =
            originalPacket.copyOfRange(
                16,
                20
            )

        val udpLength =
            UDP_HEADER_LENGTH +
                dnsResponse.size

        val ipLength =
            IPV4_HEADER_LENGTH +
                udpLength

        val responsePacket =
            ByteArray(
                ipLength
            )

        // --------------------------------------------------------
        // IPv4 HEADER
        // --------------------------------------------------------

        /*
         * Version 4
         * IHL 5
         */
        responsePacket[0] =
            0x45.toByte()

        /*
         * DSCP / ECN
         */
        responsePacket[1] =
            originalPacket[1]

        /*
         * Total length.
         */
        writeUnsignedShort(
            responsePacket,
            2,
            ipLength
        )

        /*
         * Copy identification.
         */
        responsePacket[4] =
            originalPacket[4]

        responsePacket[5] =
            originalPacket[5]

        /*
         * Fragmentation flags/offset = 0
         */
        responsePacket[6] =
            0

        responsePacket[7] =
            0

        /*
         * TTL.
         */
        responsePacket[8] =
            64

        /*
         * UDP.
         */
        responsePacket[9] =
            UDP_PROTOCOL.toByte()

        /*
         * Checksum initially zero.
         */
        responsePacket[10] =
            0

        responsePacket[11] =
            0

        /*
         * Reverse IP addresses.
         */
        System.arraycopy(
            originalDestinationIp,
            0,
            responsePacket,
            12,
            4
        )

        System.arraycopy(
            originalSourceIp,
            0,
            responsePacket,
            16,
            4
        )

        /*
         * IPv4 checksum.
         */
        val ipChecksum =
            calculateChecksum(
                responsePacket,
                0,
                IPV4_HEADER_LENGTH
            )

        writeUnsignedShort(
            responsePacket,
            10,
            ipChecksum
        )

        // --------------------------------------------------------
        // UDP HEADER
        // --------------------------------------------------------

        /*
         * Reverse source/destination ports.
         */
        writeUnsignedShort(
            responsePacket,
            20,
            destinationPort
        )

        writeUnsignedShort(
            responsePacket,
            22,
            sourcePort
        )

        writeUnsignedShort(
            responsePacket,
            24,
            udpLength
        )

        /*
         * UDP checksum = 0.
         *
         * UDP checksum zero is valid for IPv4.
         */
        responsePacket[26] =
            0

        responsePacket[27] =
            0

        // --------------------------------------------------------
        // DNS
        // --------------------------------------------------------

        System.arraycopy(
            dnsResponse,
            0,
            responsePacket,
            IPV4_HEADER_LENGTH +
                UDP_HEADER_LENGTH,
            dnsResponse.size
        )

        try {

            output.write(
                responsePacket
            )

            output.flush()

        } catch (e: Exception) {

            if (running.get()) {

                android.util.Log.w(
                    TAG,
                    "Failed to write DNS response",
                    e
                )
            }
        }
    }

    // ============================================================
    // FILTER REFRESH
    // ============================================================

    private fun startFilterRefresh() {

        filterJob?.cancel()

        filterJob =
            serviceScope.launch {

                /*
                 * Initial update.
                 */
                try {

                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )

                } catch (e: Exception) {

                    android.util.Log.w(
                        TAG,
                        "Initial filter update failed",
                        e
                    )
                }

                /*
                 * Periodic update.
                 */
                while (
                    isActive &&
                    running.get()
                ) {

                    delay(
                        FILTER_REFRESH_MS
                    )

                    if (!running.get()) {
                        break
                    }

                    try {

                        FilterManager.updateFilters(
                            this@AdBlockVpnService
                        )

                    } catch (e: Exception) {

                        android.util.Log.w(
                            TAG,
                            "Filter refresh failed",
                            e
                        )
                    }
                }
            }
    }

    // ============================================================
    // NOTIFICATION
    // ============================================================

    private fun updateDiagnosticNotification() {

        if (!running.get()) {
            return
        }

        updateNotification(
            "DNS: $dnsQueryCount  •  " +
                "Blocked: $blockedDnsCount  •  " +
                "Forwarded: $forwardedDnsCount"
        )
    }

    private fun updateNotification(
        text: String
    ) {

        try {

            val manager =
                getSystemService(
                    NotificationManager::class.java
                )

            manager.notify(
                NOTIFICATION_ID,
                createNotification(text)
            )

        } catch (e: Exception) {

            android.util.Log.w(
                TAG,
                "Notification update failed",
                e
            )
        }
    }

    private fun createNotification(
        text: String
    ): Notification {

        return NotificationCompat
            .Builder(
                this,
                CHANNEL_ID
            )
            .setContentTitle(
                "DNS Ad Blocker"
            )
            .setContentText(
                text
            )
            .setSmallIcon(
                android.R.drawable.stat_sys_warning
            )
            .setOngoing(true)
            .setCategory(
                NotificationCompat.CATEGORY_SERVICE
            )
            .setPriority(
                NotificationCompat.PRIORITY_LOW
            )
            .build()
    }

    private fun createNotificationChannel() {

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.O
        ) {
            return
        }

        val manager =
            getSystemService(
                NotificationManager::class.java
            )

        val channel =
            NotificationChannel(
                CHANNEL_ID,
                "DNS Ad Blocker",
                NotificationManager.IMPORTANCE_LOW
            )

        channel.description =
            "DNS ad and tracker blocking"

        manager.createNotificationChannel(
            channel
        )
    }

    // ============================================================
    // CHECKSUM
    // ============================================================

    private fun calculateChecksum(
        data: ByteArray,
        offset: Int,
        length: Int
    ): Int {

        var sum = 0L

        var index =
            offset

        val end =
            offset + length

        while (
            index + 1 < end
        ) {

            val word =
                (
                    ((data[index].toInt() and 0xFF) shl 8) or
                        (data[index + 1].toInt() and 0xFF)
                    )

            sum +=
                word.toLong()

            while (
                (sum ushr 16) != 0L
            ) {

                sum =
                    (sum and 0xFFFFL) +
                        (sum ushr 16)
            }

            index += 2
        }

        if (index < end) {

            sum +=
                ((data[index].toInt() and 0xFF)
                    .toLong() shl 8)
        }

        while (
            (sum ushr 16) != 0L
        ) {

            sum =
                (sum and 0xFFFFL) +
                    (sum ushr 16)
        }

        return (
            sum.inv() and 0xFFFFL
            ).toInt()
    }

    // ============================================================
    // BYTE HELPERS
    // ============================================================

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
            ((value ushr 8) and 0xFF)
                .toByte()

        data[offset + 1] =
            (value and 0xFF)
                .toByte()
    }

    // ============================================================
    // STOP VPN
    // ============================================================

    private fun stopVpn() {

        if (
            !running.get() &&
            vpnInterface == null
        ) {
            isRunning = false
            return
        }

        running.set(false)

        isRunning = false

        /*
         * Cancel coroutines first.
         */
        packetJob?.cancel()
        packetJob = null

        filterJob?.cancel()
        filterJob = null

        /*
         * Closing the streams also unblocks
         * a read() waiting on the TUN interface.
         */
        try {
            inputStream?.close()
        } catch (_: Exception) {
        }

        inputStream = null

        try {
            outputStream?.close()
        } catch (_: Exception) {
        }

        outputStream = null

        /*
         * Close VPN interface.
         */
        val descriptor =
            vpnInterface

        vpnInterface = null

        try {
            descriptor?.close()
        } catch (_: Exception) {
        }

        /*
         * Stop foreground service.
         *
         * Use the deprecated-compatible form because
         * it works across older Android API levels and
         * avoids the STOP_FOREGROUND_REMOVE compilation
         * problem from the previous version.
         */
        try {

            @Suppress("DEPRECATION")
            stopForeground(true)

        } catch (_: Exception) {
        }

        stopSelf()
    }

    // ============================================================
    // VPN REVOKED
    // ============================================================

    override fun onRevoke() {

        stopVpn()

        super.onRevoke()
    }

    // ============================================================
    // DESTROY
    // ============================================================

    override fun onDestroy() {

        stopVpn()

        serviceScope.cancel()

        super.onDestroy()
    }

    // ============================================================
    // BIND
    // ============================================================

    override fun onBind(
        intent: Intent?
    ): IBinder? {

        return super.onBind(intent)
    }
}

package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
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
         * VPN interface address.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        /*
         * DNS address exposed through VPN.
         */
        private const val DNS_ADDRESS =
            "10.8.0.1"

        /*
         * Upstream DNS resolver.
         */
        private const val UPSTREAM_DNS =
            "8.8.8.8"

        private const val DNS_PORT =
            53

        private const val MTU =
            1500

        private const val IPV4_HEADER_LENGTH =
            20

        private const val UDP_HEADER_LENGTH =
            8

        private const val DNS_HEADER_LENGTH =
            12

        private const val UDP_PROTOCOL =
            17

        private const val MAX_PACKET_SIZE =
            32767

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val DNS_TIMEOUT_MS =
            3000

        private const val FILTER_REFRESH_MS =
            12L * 60L * 60L * 1000L

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    // =====================================================
    // VPN
    // =====================================================

    private var vpnInterface:
        ParcelFileDescriptor? = null

    private var inputStream:
        FileInputStream? = null

    private var outputStream:
        FileOutputStream? = null

    // =====================================================
    // COROUTINES
    // =====================================================

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )

    private var packetJob:
        Job? = null

    private var filterRefreshJob:
        Job? = null

    // =====================================================
    // STATE
    // =====================================================

    private val running =
        AtomicBoolean(false)

    /*
     * Diagnostic counters.
     *
     * These are displayed in the VPN notification.
     */
    @Volatile
    private var dnsQueryCount =
        0

    @Volatile
    private var blockedDnsCount =
        0

    @Volatile
    private var forwardedDnsCount =
        0

    // =====================================================
    // SERVICE CREATE
    // =====================================================

    override fun onCreate() {

        super.onCreate()

        createNotificationChannel()
    }

    // =====================================================
    // START COMMAND
    // =====================================================

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        when (intent?.action) {

            ACTION_STOP -> {

                stopVpn()

                return START_NOT_STICKY
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

    // =====================================================
    // START VPN
    // =====================================================

    private fun startVpn() {

        if (running.get()) {
            return
        }

        if (
            !AdBlockStorage.isEnabled(
                this
            )
        ) {

            stopSelf()

            return
        }

        /*
         * Reset diagnostics.
         */
        dnsQueryCount = 0
        blockedDnsCount = 0
        forwardedDnsCount = 0

        try {

            updateNotification(
                "Starting VPN..."
            )

            /*
             * Build VPN interface.
             */
            val builder =
                Builder()
                    .setSession(
                        getString(
                            R.string.app_name
                        )
                    )
                    .setMtu(
                        MTU
                    )
                    .addAddress(
                        VPN_ADDRESS,
                        VPN_PREFIX
                    )
                    .addDnsServer(
                        DNS_ADDRESS
                    )
                    .addRoute(
                        DNS_ADDRESS,
                        32
                    )

            /*
             * Do not route our own app through VPN.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (error: Exception) {

                android.util.Log.w(
                    TAG,
                    "Unable to exclude own application",
                    error
                )
            }

            /*
             * Establish VPN.
             */
            val established =
                builder.establish()

            if (
                established == null
            ) {

                updateNotification(
                    "VPN could not start"
                )

                android.util.Log.e(
                    TAG,
                    "VPN establish returned null"
                )

                stopVpn()

                return
            }

            vpnInterface =
                established

            /*
             * Use immutable reference.
             */
            val descriptor =
                established.fileDescriptor

            inputStream =
                FileInputStream(
                    descriptor
                )

            outputStream =
                FileOutputStream(
                    descriptor
                )

            running.set(true)

            isRunning = true

            /*
             * Start foreground service.
             */
            startForeground(
                NOTIFICATION_ID,
                createNotification(
                    "VPN active • DNS queries: 0"
                )
            )

            /*
             * Packet reader.
             */
            startPacketLoop()

            /*
             * Filter update.
             */
            startFilterRefreshLoop()

            android.util.Log.i(
                TAG,
                "DNS VPN started"
            )

        } catch (error: Exception) {

            android.util.Log.e(
                TAG,
                "VPN start failed",
                error
            )

            updateNotification(
                "VPN error: ${error.message}"
            )

            stopVpn()
        }
    }

    // =====================================================
    // PACKET LOOP
    // =====================================================

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

                        val count =
                            input.read(
                                buffer
                            )

                        if (
                            count <= 0
                        ) {
                            continue
                        }

                        val packet =
                            buffer.copyOf(
                                count
                            )

                        processIpv4Packet(
                            packet
                        )

                    } catch (
                        error: Exception
                    ) {

                        if (
                            running.get()
                        ) {

                            android.util.Log.w(
                                TAG,
                                "VPN packet read failed",
                                error
                            )
                        }

                        break
                    }
                }
            }
    }

    // =====================================================
    // IPv4
    // =====================================================

    private fun processIpv4Packet(
        packet: ByteArray
    ) {

        if (
            packet.size <
            IPV4_HEADER_LENGTH
        ) {
            return
        }

        val version =
            (
                packet[0].toInt()
                    ushr 4
                ) and 0x0F

        if (
            version != 4
        ) {
            return
        }

        val ipHeaderLength =
            (
                packet[0].toInt()
                    and 0x0F
                ) * 4

        if (
            ipHeaderLength <
            IPV4_HEADER_LENGTH
        ) {
            return
        }

        if (
            ipHeaderLength >
            packet.size
        ) {
            return
        }

        val totalLength =
            readUnsignedShort(
                packet,
                2
            )

        if (
            totalLength <
            ipHeaderLength
        ) {
            return
        }

        if (
            totalLength >
            packet.size
        ) {
            return
        }

        val protocol =
            packet[9].toInt() and 0xFF

        /*
         * DNS filtering currently handles
         * UDP DNS only.
         */
        if (
            protocol != UDP_PROTOCOL
        ) {
            return
        }

        processUdpPacket(
            packet,
            totalLength,
            ipHeaderLength
        )
    }

    // =====================================================
    // UDP
    // =====================================================

    private fun processUdpPacket(
        packet: ByteArray,
        totalLength: Int,
        ipHeaderLength: Int
    ) {

        val udpOffset =
            ipHeaderLength

        if (
            totalLength <
            udpOffset +
            UDP_HEADER_LENGTH
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
            udpLength <
            UDP_HEADER_LENGTH
        ) {
            return
        }

        if (
            udpOffset +
            udpLength >
            totalLength
        ) {
            return
        }

        /*
         * We only process DNS port 53.
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
            dnsLength <
            DNS_HEADER_LENGTH
        ) {
            return
        }

        if (
            dnsOffset +
            dnsLength >
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
            originalPacket =
                packet,

            originalLength =
                totalLength,

            ipHeaderLength =
                ipHeaderLength,

            sourcePort =
                sourcePort,

            destinationPort =
                destinationPort,

            dnsQuery =
                dnsQuery
        )
    }

    // =====================================================
    // DNS QUERY
    // =====================================================

    private fun handleDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        /*
         * DIAGNOSTIC COUNTER
         */
        dnsQueryCount++

        updateDiagnosticNotification()

        /*
         * Extract hostname.
         */
        val hostname =
            parseDnsQuestionName(
                dnsQuery
            )

        /*
         * Unknown DNS packet.
         *
         * Forward instead of dropping.
         */
        if (
            hostname.isNullOrBlank()
        ) {

            forwardedDnsCount++

            forwardDnsQuery(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsQuery
            )

            return
        }

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase()

        android.util.Log.d(
            TAG,
            "DNS HOSTNAME: $normalized"
        )

        /*
         * Allowlist has priority.
         */
        if (
            isAllowlisted(
                normalized
            )
        ) {

            forwardedDnsCount++

            forwardDnsQuery(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsQuery
            )

            return
        }

        /*
         * Check filter.
         */
        val blocked =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (
                error: Exception
            ) {

                android.util.Log.e(
                    TAG,
                    "FilterManager error",
                    error
                )

                /*
                 * Fail open.
                 */
                false
            }

        android.util.Log.d(
            TAG,
            "DNS BLOCK RESULT: $normalized -> $blocked"
        )

        if (blocked) {

            blockedDnsCount++

            AdBlockStorage.incrementBlockedCount(
                this
            )

            updateDiagnosticNotification()

            android.util.Log.d(
                TAG,
                "BLOCKED DNS: $normalized"
            )

            val blockedResponse =
                buildBlockedDnsResponse(
                    dnsQuery
                )

            if (
                blockedResponse != null
            ) {

                writeDnsResponse(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    destinationPort,
                    blockedResponse
                )
            }

            return
        }

        /*
         * Allowed DNS request.
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

    // =====================================================
    // ALLOWLIST
    // =====================================================

    private fun isAllowlisted(
        hostname: String
    ): Boolean {

        val allowlist =
            try {

                AdBlockStorage.getAllowlist(
                    this
                )

            } catch (
                error: Exception
            ) {

                android.util.Log.w(
                    TAG,
                    "Could not read allowlist",
                    error
                )

                emptySet()
            }

        if (
            allowlist.isEmpty()
        ) {
            return false
        }

        val normalizedAllowlist =
            allowlist
                .map {
                    it
                        .trim()
                        .trim('.')
                        .lowercase()
                }
                .toSet()

        if (
            normalizedAllowlist.contains(
                hostname
            )
        ) {
            return true
        }

        /*
         * Parent-domain matching.
         *
         * Example:
         *
         * allowlist:
         * example.com
         *
         * query:
         * ads.example.com
         *
         * => allowed
         */
        var current =
            hostname

        while (true) {

            val dot =
                current.indexOf('.')

            if (
                dot < 0
            ) {
                break
            }

            current =
                current.substring(
                    dot + 1
                )

            if (
                normalizedAllowlist.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
    }

    // =====================================================
    // DNS NAME PARSER
    // =====================================================

    private fun parseDnsQuestionName(
        dnsPacket: ByteArray
    ): String? {

        if (
            dnsPacket.size <
            DNS_HEADER_LENGTH + 1
        ) {
            return null
        }

        /*
         * QDCOUNT.
         */
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
            mutableListOf<String>()

        var labelCount =
            0

        while (
            position <
            dnsPacket.size
        ) {

            if (
                labelCount >
                127
            ) {
                return null
            }

            val length =
                dnsPacket[position]
                    .toInt() and 0xFF

            position++

            /*
             * End of QNAME.
             */
            if (
                length == 0
            ) {
                break
            }

            /*
             * Compression pointer.
             *
             * We don't process compressed question names.
             */
            if (
                (length and 0xC0) != 0
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

            if (
                label.isEmpty()
            ) {
                return null
            }

            labels.add(
                label
            )

            labelCount++

            position += length
        }

        if (
            labels.isEmpty()
        ) {
            return null
        }

        return labels
            .joinToString(".")
            .lowercase()
    }

    // =====================================================
    // BLOCK DNS
    // =====================================================

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
         * Preserve question.
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
            originalFlags and
            0x0100 != 0
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
         * RCODE = NXDOMAIN
         */
        flags =
            flags or 0x0003

        writeUnsignedShort(
            response,
            2,
            flags
        )

        /*
         * QDCOUNT
         */
        writeUnsignedShort(
            response,
            4,
            1
        )

        /*
         * ANCOUNT
         */
        writeUnsignedShort(
            response,
            6,
            0
        )

        /*
         * NSCOUNT
         */
        writeUnsignedShort(
            response,
            8,
            0
        )

        /*
         * ARCOUNT
         */
        writeUnsignedShort(
            response,
            10,
            0
        )

        return response
    }

    // =====================================================
    // FORWARD DNS
    // =====================================================

    private fun forwardDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        var socket:
            DatagramSocket? = null

        try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL:
             *
             * Protect upstream socket from VPN.
             */
            if (
                !protect(socket)
            ) {

                android.util.Log.e(
                    TAG,
                    "Could not protect DNS socket"
                )

                return
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val upstream =
                InetSocketAddress(
                    UPSTREAM_DNS,
                    DNS_PORT
                )

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    upstream
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
             * Validate transaction ID.
             */
            if (
                dnsQuery.size >= 2 &&
                response.size >= 2
            ) {

                val queryId =
                    (
                        ((dnsQuery[0].toInt() and 0xFF) shl 8) or
                            (dnsQuery[1].toInt() and 0xFF)
                        )

                val responseId =
                    (
                        ((response[0].toInt() and 0xFF) shl 8) or
                            (response[1].toInt() and 0xFF)
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

        } catch (
            error: Exception
        ) {

            android.util.Log.w(
                TAG,
                "Upstream DNS request failed",
                error
            )

        } finally {

            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    // =====================================================
    // WRITE DNS RESPONSE
    // =====================================================

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

        if (
            dnsResponse.isEmpty()
        ) {
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
         * device -> VPN DNS
         *
         * Response:
         *
         * VPN DNS -> device
         */
        val sourceIp =
            originalPacket.copyOfRange(
                12,
                16
            )

        val destinationIp =
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

        if (
            ipLength > 65535
        ) {
            return
        }

        val responsePacket =
            ByteArray(
                ipLength
            )

        // =================================================
        // IPv4
        // =================================================

        responsePacket[0] =
            0x45.toByte()

        responsePacket[1] =
            0

        writeUnsignedShort(
            responsePacket,
            2,
            ipLength
        )

        /*
         * Preserve ID.
         */
        responsePacket[4] =
            originalPacket[4]

        responsePacket[5] =
            originalPacket[5]

        /*
         * Fragment offset = 0.
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
         * Reverse IPs.
         */
        System.arraycopy(
            destinationIp,
            0,
            responsePacket,
            12,
            4
        )

        System.arraycopy(
            sourceIp,
            0,
            responsePacket,
            16,
            4
        )

        /*
         * Calculate IPv4 checksum.
         */
        val checksum =
            calculateChecksum(
                responsePacket,
                0,
                IPV4_HEADER_LENGTH
            )

        writeUnsignedShort(
            responsePacket,
            10,
            checksum
        )

        // =================================================
        // UDP
        // =================================================

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
         * UDP checksum = 0 for IPv4.
         */
        responsePacket[26] =
            0

        responsePacket[27] =
            0

        // =================================================
        // DNS
        // =================================================

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

        } catch (
            error: Exception
        ) {

            if (
                running.get()
            ) {

                android.util.Log.w(
                    TAG,
                    "Could not write DNS response",
                    error
                )
            }
        }
    }

    // =====================================================
    // DIAGNOSTIC NOTIFICATION
    // =====================================================

    private fun updateDiagnosticNotification() {

        if (!running.get()) {
            return
        }

        val text =
            "DNS: $dnsQueryCount • " +
                "Blocked: $blockedDnsCount • " +
                "Forwarded: $forwardedDnsCount"

        updateNotification(
            text
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
                createNotification(
                    text
                )
            )

        } catch (
            error: Exception
        ) {

            android.util.Log.w(
                TAG,
                "Could not update notification",
                error
            )
        }
    }

    // =====================================================
    // FILTER REFRESH
    // =====================================================

    private fun startFilterRefreshLoop() {

        filterRefreshJob?.cancel()

        filterRefreshJob =
            serviceScope.launch {

                /*
                 * Load filters immediately.
                 */
                try {

                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )

                } catch (
                    error: Exception
                ) {

                    android.util.Log.w(
                        TAG,
                        "Initial filter update failed",
                        error
                    )
                }

                while (
                    isActive &&
                    running.get()
                ) {

                    delay(
                        FILTER_REFRESH_MS
                    )

                    if (
                        !running.get()
                    ) {
                        break
                    }

                    try {

                        FilterManager.updateFilters(
                            this@AdBlockVpnService
                        )

                    } catch (
                        error: Exception
                    ) {

                        android.util.Log.w(
                            TAG,
                            "Filter refresh failed",
                            error
                        )
                    }
                }
            }
    }

    // =====================================================
    // STOP VPN
    // =====================================================

    private fun stopVpn() {

        running.set(false)

        isRunning = false

        packetJob?.cancel()

        packetJob = null

        filterRefreshJob?.cancel()

        filterRefreshJob = null

        /*
         * Close streams.
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
        val interfaceToClose =
            vpnInterface

        vpnInterface = null

        try {
            interfaceToClose?.close()
        } catch (_: Exception) {
        }

        /*
         * Remove foreground notification.
         */
        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.N
        ) {

            stopForeground(
                STOP_FOREGROUND_REMOVE
            )

        } else {

            @Suppress("DEPRECATION")
            stopForeground(
                true
            )
        }

        stopSelf()
    }

    // =====================================================
    // NOTIFICATION
    // =====================================================

    private fun createNotification(
        text: String
    ): Notification {

        return NotificationCompat
            .Builder(
                this,
                CHANNEL_ID
            )
            .setContentTitle(
                getString(
                    R.string.app_name
                )
            )
            .setContentText(
                text
            )
            .setSmallIcon(
                android.R.drawable.ic_secure
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
                "Ad Blocker VPN",
                NotificationManager.IMPORTANCE_LOW
            )

        channel.description =
            "DNS ad and tracker blocking"

        manager.createNotificationChannel(
            channel
        )
    }

    // =====================================================
    // CHECKSUM
    // =====================================================

    private fun calculateChecksum(
        data: ByteArray,
        offset: Int,
        length: Int
    ): Int {

        var sum =
            0L

        var index =
            offset

        val end =
            offset + length

        while (
            index + 1 <
            end
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

        if (
            index < end
        ) {

            sum +=
                (
                    (data[index].toInt() and 0xFF)
                        .toLong() shl 8
                    )
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

    // =====================================================
    // BYTE UTILITIES
    // =====================================================

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

    // =====================================================
    // LIFECYCLE
    // =====================================================

    override fun onRevoke() {

        stopVpn()

        super.onRevoke()
    }

    override fun onDestroy() {

        stopVpn()

        serviceScope.cancel()

        super.onDestroy()
    }

    override fun onBind(
        intent: Intent?
    ): IBinder? {

        return super.onBind(
            intent
        )
    }
}

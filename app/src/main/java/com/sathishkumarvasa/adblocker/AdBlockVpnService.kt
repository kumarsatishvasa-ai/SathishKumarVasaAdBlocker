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
         * Virtual VPN address.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        /*
         * DNS address exposed through the VPN.
         *
         * Applications send DNS packets to this address.
         */
        private const val DNS_ADDRESS =
            "10.8.0.1"

        /*
         * Primary and backup upstream DNS servers.
         *
         * Both sockets are protected so they bypass our VPN.
         */
        private const val PRIMARY_DNS =
            "1.1.1.1"

        private const val SECONDARY_DNS =
            "8.8.8.8"

        private const val DNS_PORT =
            53

        private const val DNS_TIMEOUT_MS =
            1800

        private const val MAX_PACKET_SIZE =
            32767

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val IPV4_MIN_HEADER =
            20

        private const val UDP_HEADER =
            8

        private const val DNS_HEADER =
            12

        private const val UDP_PROTOCOL =
            17

        private const val FILTER_REFRESH_MS =
            12L * 60L * 60L * 1000L

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface:
        ParcelFileDescriptor? = null

    private var inputStream:
        FileInputStream? = null

    private var outputStream:
        FileOutputStream? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )

    private var packetJob:
        Job? = null

    private var filterJob:
        Job? = null

    private val running =
        AtomicBoolean(false)

    @Volatile
    private var dnsQueryCount =
        0

    @Volatile
    private var blockedDnsCount =
        0

    @Volatile
    private var forwardedDnsCount =
        0

    /*
     * FileOutputStream writes are serialized because the VPN
     * interface can receive multiple requests.
     */
    private val outputLock =
        Any()

    // ============================================================
    // SERVICE LIFECYCLE
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
             * This VPN does NOT route:
             *
             *     0.0.0.0/0
             *
             * through itself.
             *
             * Only traffic addressed to DNS_ADDRESS is routed
             * into the VPN.
             */
            val builder =
                Builder()
                    .setSession(
                        applicationLabel()
                    )
                    .setMtu(1500)
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
             * Prevent our own application from sending its
             * networking through this VPN.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (e: Exception) {

                LogWarning(
                    "Could not exclude own application: ${e.message}"
                )
            }

            val established =
                builder.establish()

            if (established == null) {

                LogError(
                    "VpnService.Builder.establish() returned null"
                )

                updateNotification(
                    "Could not establish VPN"
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

            LogInfo(
                "DNS VPN started"
            )

        } catch (e: Exception) {

            LogError(
                "VPN startup failed",
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

                        val count =
                            input.read(buffer)

                        if (count <= 0) {
                            continue
                        }

                        val packet =
                            buffer.copyOf(count)

                        processPacket(packet)

                    } catch (e: Exception) {

                        if (running.get()) {

                            LogWarning(
                                "VPN packet read failed: ${e.message}"
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
        packet: ByteArray
    ) {

        if (
            packet.size <
            IPV4_MIN_HEADER
        ) {
            return
        }

        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        /*
         * This implementation deliberately handles IPv4 only.
         *
         * The VPN does not route normal IPv6 Internet traffic.
         */
        if (version != 4) {
            return
        }

        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ipHeaderLength < IPV4_MIN_HEADER ||
            ipHeaderLength > packet.size
        ) {
            return
        }

        val totalLength =
            readUnsignedShort(
                packet,
                2
            )

        if (
            totalLength < ipHeaderLength ||
            totalLength > packet.size
        ) {
            return
        }

        val protocol =
            packet[9].toInt() and 0xFF

        /*
         * DNS is normally UDP.
         *
         * TCP DNS is intentionally not intercepted here.
         *
         * Because this VPN is configured only around the local
         * DNS endpoint, ordinary application TCP/443 traffic is
         * not routed through this VPN.
         */
        if (protocol != UDP_PROTOCOL) {
            return
        }

        processUdpPacket(
            packet,
            totalLength,
            ipHeaderLength
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
            udpOffset + UDP_HEADER
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
            udpLength < UDP_HEADER
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
         * We only process packets addressed to DNS port 53.
         */
        if (
            destinationPort != DNS_PORT
        ) {
            return
        }

        val dnsOffset =
            udpOffset + UDP_HEADER

        val dnsLength =
            udpLength - UDP_HEADER

        if (
            dnsLength < DNS_HEADER
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

        val hostname =
            parseDnsQuestionName(
                dnsQuery
            )

        /*
         * If parsing fails, DO NOT block.
         *
         * This is important for compatibility.
         */
        if (hostname == null) {

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

        LogInfo(
            "DNS query: $normalized"
        )

        /*
         * Allowlist has priority.
         */
        if (
            isAllowlisted(normalized)
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

            updateDiagnosticNotification()

            return
        }

        /*
         * Ask ONLY FilterManager whether this hostname is blocked.
         */
        val blocked =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (e: Exception) {

                LogWarning(
                    "Filter check failed: ${e.message}"
                )

                /*
                 * FAIL OPEN.
                 *
                 * A filter problem must not make the Internet
                 * stop working.
                 */
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

            LogInfo(
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
            }

        } else {

            forwardedDnsCount++

            LogInfo(
                "FORWARDED: $normalized"
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
    // ALLOWLIST
    // ============================================================

    private fun isAllowlisted(
        hostname: String
    ): Boolean {

        val allowlist =
            try {

                AdBlockStorage
                    .getAllowlist(this)
                    .map {
                        it.trim()
                            .trim('.')
                            .lowercase(Locale.US)
                    }
                    .filter {
                        it.isNotEmpty()
                    }
                    .toSet()

            } catch (_: Exception) {

                emptySet()
            }

        if (allowlist.isEmpty()) {
            return false
        }

        if (
            allowlist.contains(hostname)
        ) {
            return true
        }

        /*
         * Parent-domain allowlisting.
         */
        var current =
            hostname

        while (true) {

            val dot =
                current.indexOf('.')

            if (dot < 0) {
                break
            }

            current =
                current.substring(
                    dot + 1
                )

            if (
                allowlist.contains(current)
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // DNS QUESTION PARSER
    // ============================================================

    private fun parseDnsQuestionName(
        dnsPacket: ByteArray
    ): String? {

        if (
            dnsPacket.size <
            DNS_HEADER
        ) {
            return null
        }

        /*
         * QR bit must be 0 for a query.
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
            DNS_HEADER

        val labels =
            ArrayList<String>()

        while (
            position < dnsPacket.size
        ) {

            val length =
                dnsPacket[position]
                    .toInt() and 0xFF

            position++

            if (length == 0) {
                break
            }

            /*
             * Compression pointers are not expected in the
             * question name. Reject instead of guessing.
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

            if (
                label.isEmpty()
            ) {
                return null
            }

            labels.add(label)

            position += length

            if (
                labels.size > 127
            ) {
                return null
            }
        }

        if (
            labels.isEmpty()
        ) {
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
            DNS_HEADER
        ) {
            return null
        }

        /*
         * Preserve the original question.
         */
        val response =
            query.copyOf()

        val originalFlags =
            readUnsignedShort(
                query,
                2
            )

        /*
         * Response.
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
         * Recursion available.
         */
        flags =
            flags or 0x0080

        /*
         * NXDOMAIN.
         */
        flags =
            flags or 0x0003

        writeUnsignedShort(
            response,
            2,
            flags
        )

        /*
         * One question.
         */
        writeUnsignedShort(
            response,
            4,
            1
        )

        /*
         * No answer.
         */
        writeUnsignedShort(
            response,
            6,
            0
        )

        /*
         * No authority.
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
    // UPSTREAM DNS
    // ============================================================

    private fun forwardDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        /*
         * Try Cloudflare first, then Google.
         *
         * The second resolver is important because a temporary
         * failure of one upstream should not make Chrome/YouTube
         * appear offline.
         */
        val upstreams =
            arrayOf(
                PRIMARY_DNS,
                SECONDARY_DNS
            )

        var response:
            ByteArray? = null

        for (server in upstreams) {

            response =
                queryUpstreamDns(
                    server,
                    dnsQuery
                )

            if (response != null) {
                break
            }
        }

        if (response == null) {

            /*
             * There is no safe packet to inject if every upstream
             * DNS server failed.
             *
             * Log it clearly rather than returning a bogus DNS
             * response.
             */
            LogWarning(
                "All upstream DNS servers failed"
            )

            return
        }

        writeDnsResponse(
            originalPacket,
            originalLength,
            ipHeaderLength,
            sourcePort,
            destinationPort,
            response
        )
    }

    private fun queryUpstreamDns(
        server: String,
        dnsQuery: ByteArray
    ): ByteArray? {

        var socket:
            DatagramSocket? = null

        return try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL:
             *
             * Without protect(), the upstream DNS socket can be
             * captured by our own VPN route and loop back into the
             * service.
             *
             * Android explicitly provides VpnService.protect()
             * for this purpose.
             */
            if (!protect(socket)) {

                LogWarning(
                    "protect() failed for DNS socket $server"
                )

                return null
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    InetSocketAddress(
                        server,
                        DNS_PORT
                    )
                )

            socket.send(request)

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
                return null
            }

            val response =
                responsePacket.data
                    .copyOf(
                        responsePacket.length
                    )

            /*
             * DNS transaction ID must match.
             */
            if (
                !sameDnsTransactionId(
                    dnsQuery,
                    response
                )
            ) {

                LogWarning(
                    "DNS transaction ID mismatch from $server"
                )

                return null
            }

            /*
             * Make sure this is actually a DNS response.
             */
            if (
                response.size < DNS_HEADER
            ) {
                return null
            }

            val flags =
                readUnsignedShort(
                    response,
                    2
                )

            if (
                flags and 0x8000 == 0
            ) {
                return null
            }

            response

        } catch (e: Exception) {

            LogWarning(
                "Upstream DNS $server failed: ${e.message}"
            )

            null

        } finally {

            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    // ============================================================
    // DNS TRANSACTION ID
    // ============================================================

    private fun sameDnsTransactionId(
        query: ByteArray,
        response: ByteArray
    ): Boolean {

        if (
            query.size < 2 ||
            response.size < 2
        ) {
            return false
        }

        return query[0] == response[0] &&
            query[1] == response[1]
    }

    // ============================================================
    // WRITE DNS RESPONSE INTO VPN
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

        if (
            dnsResponse.isEmpty()
        ) {
            return
        }

        if (
            originalPacket.size <
            ipHeaderLength
        ) {
            return
        }

        val udpLength =
            UDP_HEADER +
                dnsResponse.size

        val ipLength =
            ipHeaderLength +
                udpLength

        if (
            ipLength > 65535
        ) {
            return
        }

        val responsePacket =
            ByteArray(ipLength)

        /*
         * Copy the original IPv4 header first.
         *
         * Then replace source/destination addresses and
         * recompute the IP checksum.
         */
        System.arraycopy(
            originalPacket,
            0,
            responsePacket,
            0,
            ipHeaderLength
        )

        /*
         * Reverse source and destination IP addresses.
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
         * Set the total IPv4 packet length.
         */
        writeUnsignedShort(
            responsePacket,
            2,
            ipLength
        )

        /*
         * Clear and recalculate IP checksum.
         */
        responsePacket[10] =
            0

        responsePacket[11] =
            0

        val ipChecksum =
            calculateChecksum(
                responsePacket,
                0,
                ipHeaderLength
            )

        writeUnsignedShort(
            responsePacket,
            10,
            ipChecksum
        )

        /*
         * UDP header begins immediately after the IPv4 header.
         */
        val udpOffset =
            ipHeaderLength

        /*
         * Response source port = DNS port.
         */
        writeUnsignedShort(
            responsePacket,
            udpOffset,
            destinationPort
        )

        /*
         * Response destination port = original source port.
         */
        writeUnsignedShort(
            responsePacket,
            udpOffset + 2,
            sourcePort
        )

        writeUnsignedShort(
            responsePacket,
            udpOffset + 4,
            udpLength
        )

        /*
         * UDP checksum 0 is legal for IPv4.
         */
        responsePacket[udpOffset + 6] =
            0

        responsePacket[udpOffset + 7] =
            0

        /*
         * DNS payload.
         */
        System.arraycopy(
            dnsResponse,
            0,
            responsePacket,
            udpOffset + UDP_HEADER,
            dnsResponse.size
        )

        try {

            synchronized(outputLock) {

                output.write(
                    responsePacket
                )

                output.flush()
            }

        } catch (e: Exception) {

            if (running.get()) {

                LogWarning(
                    "Could not write DNS response: ${e.message}"
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

                try {

                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )

                } catch (e: Exception) {

                    LogWarning(
                        "Initial filter update failed: ${e.message}"
                    )
                }

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

                        LogWarning(
                            "Filter refresh failed: ${e.message}"
                        )
                    }
                }
            }
    }

    // ============================================================
    // NOTIFICATION
    // ============================================================

    private fun applicationLabel(): String {

        return try {

            applicationInfo
                .loadLabel(packageManager)
                .toString()

        } catch (_: Exception) {

            "DNS Ad Blocker"
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
                applicationLabel()
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
                "Ad Blocker VPN",
                NotificationManager.IMPORTANCE_LOW
            )

        channel.description =
            "DNS ad and tracker blocking"

        manager.createNotificationChannel(
            channel
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

            LogWarning(
                "Notification update failed: ${e.message}"
            )
        }
    }

    private fun updateDiagnosticNotification() {

        if (!running.get()) {
            return
        }

        updateNotification(
            "DNS $dnsQueryCount • " +
                "Blocked $blockedDnsCount • " +
                "Forwarded $forwardedDnsCount"
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

        var sum =
            0L

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
            !running.getAndSet(false)
        ) {

            isRunning = false
        }

        isRunning = false

        packetJob?.cancel()
        packetJob = null

        filterJob?.cancel()
        filterJob = null

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

        val descriptor =
            vpnInterface

        vpnInterface = null

        try {
            descriptor?.close()
        } catch (_: Exception) {
        }

        /*
         * Use the boolean overload for maximum compatibility.
         * This avoids the STOP_FOREGROUND_REMOVE compile problem
         * you encountered earlier.
         */
        try {

            @Suppress("DEPRECATION")
            stopForeground(true)

        } catch (_: Exception) {
        }

        stopSelf()

        LogInfo(
            "DNS VPN stopped"
        )
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

    // ============================================================
    // SIMPLE LOG HELPERS
    // ============================================================

    private fun LogInfo(
        message: String
    ) {

        android.util.Log.i(
            TAG,
            message
        )
    }

    private fun LogWarning(
        message: String
    ) {

        android.util.Log.w(
            TAG,
            message
        )
    }

    private fun LogError(
        message: String
    ) {

        android.util.Log.e(
            TAG,
            message
        )
    }

    private fun LogError(
        message: String,
        throwable: Throwable
    ) {

        android.util.Log.e(
            TAG,
            message,
            throwable
        )
    }
}

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
         * Private address used by the VPN interface.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        /*
         * DNS address exposed through the VPN.
         */
        private const val DNS_ADDRESS =
            "10.8.0.1"

        /*
         * Real upstream DNS server.
         */
        private const val UPSTREAM_DNS =
            "1.1.1.1"

        private const val DNS_PORT =
            53

        private const val MTU =
            1500

        private const val MAX_PACKET_SIZE =
            32767

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val DNS_TIMEOUT_MS =
            3000

        private const val IPV4_HEADER_SIZE =
            20

        private const val UDP_HEADER_SIZE =
            8

        private const val DNS_HEADER_SIZE =
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

    private val scope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO
        )

    private var packetJob: Job? = null

    private var filterJob: Job? = null

    private val running =
        AtomicBoolean(false)

    @Volatile
    private var dnsQueries = 0

    @Volatile
    private var blockedQueries = 0

    @Volatile
    private var forwardedQueries = 0

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

        dnsQueries = 0
        blockedQueries = 0
        forwardedQueries = 0

        try {

            startForeground(
                NOTIFICATION_ID,
                createNotification(
                    "Starting DNS protection..."
                )
            )

            /*
             * DNS-only VPN.
             *
             * We intentionally do NOT add:
             *
             * addRoute("0.0.0.0", 0)
             *
             * because that would make this service responsible
             * for all device traffic.
             */
            val builder =
                Builder()
                    .setSession(
                        getString(
                            com.sathishkumarvasa.adblocker.R.string.app_name
                        )
                    )
                    .setMtu(MTU)
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
             * Never send our own app traffic into its own VPN.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (e: Exception) {

                android.util.Log.w(
                    TAG,
                    "Could not exclude own package",
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

            updateNotification(
                "DNS protection active"
            )

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
            scope.launch {

                val buffer =
                    ByteArray(MAX_PACKET_SIZE)

                while (
                    isActive &&
                    running.get()
                ) {

                    val input =
                        inputStream ?: break

                    try {

                        val count =
                            input.read(buffer)

                        if (count <= 0) {
                            continue
                        }

                        processPacket(
                            buffer.copyOf(count)
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
    // IPV4 PACKET
    // ============================================================

    private fun processPacket(
        packet: ByteArray
    ) {

        if (
            packet.size < IPV4_HEADER_SIZE
        ) {
            return
        }

        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        val headerLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            headerLength < IPV4_HEADER_SIZE ||
            headerLength > packet.size
        ) {
            return
        }

        val totalLength =
            readU16(
                packet,
                2
            )

        if (
            totalLength < headerLength ||
            totalLength > packet.size
        ) {
            return
        }

        val protocol =
            packet[9].toInt() and 0xFF

        /*
         * Only UDP is handled.
         *
         * TCP/HTTPS/QUIC/etc. are intentionally ignored.
         * This prevents the service from breaking normal
         * application Internet traffic.
         */
        if (protocol != UDP_PROTOCOL) {
            return
        }

        processUdp(
            packet,
            totalLength,
            headerLength
        )
    }

    // ============================================================
    // UDP
    // ============================================================

    private fun processUdp(
        packet: ByteArray,
        totalLength: Int,
        ipHeaderLength: Int
    ) {

        val udpOffset =
            ipHeaderLength

        if (
            totalLength <
            udpOffset + UDP_HEADER_SIZE
        ) {
            return
        }

        val sourcePort =
            readU16(
                packet,
                udpOffset
            )

        val destinationPort =
            readU16(
                packet,
                udpOffset + 2
            )

        val udpLength =
            readU16(
                packet,
                udpOffset + 4
            )

        if (
            udpLength < UDP_HEADER_SIZE
        ) {
            return
        }

        if (
            udpOffset + udpLength > totalLength
        ) {
            return
        }

        /*
         * We only intercept DNS requests.
         */
        if (destinationPort != DNS_PORT) {
            return
        }

        val dnsOffset =
            udpOffset + UDP_HEADER_SIZE

        val dnsLength =
            udpLength - UDP_HEADER_SIZE

        if (
            dnsLength < DNS_HEADER_SIZE ||
            dnsOffset + dnsLength > totalLength
        ) {
            return
        }

        val dnsPacket =
            packet.copyOfRange(
                dnsOffset,
                dnsOffset + dnsLength
            )

        handleDns(
            originalPacket = packet,
            originalLength = totalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsPacket = dnsPacket
        )
    }

    // ============================================================
    // DNS
    // ============================================================

    private fun handleDns(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsPacket: ByteArray
    ) {

        dnsQueries++

        val hostname =
            parseQuestionName(
                dnsPacket
            )

        /*
         * If this isn't a DNS query we understand,
         * forward it instead of blocking it.
         */
        if (hostname == null) {

            forwardedQueries++

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsPacket
            )

            updateDiagnosticNotification()
            return
        }

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase()

        android.util.Log.d(
            TAG,
            "DNS query: $normalized"
        )

        val blocked =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (e: Exception) {

                /*
                 * Fail open.
                 *
                 * A filter problem must NEVER make
                 * Chrome or YouTube stop working.
                 */
                android.util.Log.e(
                    TAG,
                    "Filter check failed",
                    e
                )

                false
            }

        if (blocked) {

            blockedQueries++

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

            val response =
                createNxDomainResponse(
                    dnsPacket
                )

            if (response != null) {

                writeDnsResponse(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    destinationPort,
                    response
                )
            }

        } else {

            forwardedQueries++

            android.util.Log.d(
                TAG,
                "FORWARDED: $normalized"
            )

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsPacket
            )
        }

        updateDiagnosticNotification()
    }

    // ============================================================
    // DNS QUESTION NAME
    // ============================================================

    private fun parseQuestionName(
        packet: ByteArray
    ): String? {

        if (
            packet.size <
            DNS_HEADER_SIZE + 1
        ) {
            return null
        }

        val questionCount =
            readU16(
                packet,
                4
            )

        if (questionCount <= 0) {
            return null
        }

        var position =
            DNS_HEADER_SIZE

        val labels =
            ArrayList<String>()

        while (
            position < packet.size
        ) {

            val length =
                packet[position]
                    .toInt() and 0xFF

            position++

            if (length == 0) {
                break
            }

            /*
             * Compression pointer in the question name
             * is not accepted here. Forward instead.
             */
            if (
                (length and 0xC0) != 0
            ) {
                return null
            }

            if (
                length > 63 ||
                position + length > packet.size
            ) {
                return null
            }

            val label =
                String(
                    packet,
                    position,
                    length,
                    Charsets.US_ASCII
                )

            if (label.isEmpty()) {
                return null
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

        return labels.joinToString(".")
    }

    // ============================================================
    // BLOCK RESPONSE
    // ============================================================

    private fun createNxDomainResponse(
        query: ByteArray
    ): ByteArray? {

        if (
            query.size < DNS_HEADER_SIZE
        ) {
            return null
        }

        /*
         * Preserve the entire question.
         */
        val response =
            query.copyOf()

        val originalFlags =
            readU16(
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
         * RA.
         */
        flags =
            flags or 0x0080

        /*
         * NXDOMAIN.
         */
        flags =
            flags or 0x0003

        writeU16(
            response,
            2,
            flags
        )

        /*
         * Keep question count.
         */
        writeU16(
            response,
            4,
            1
        )

        /*
         * No answer/authority/additional records.
         */
        writeU16(
            response,
            6,
            0
        )

        writeU16(
            response,
            8,
            0
        )

        writeU16(
            response,
            10,
            0
        )

        return response
    }

    // ============================================================
    // FORWARD DNS
    // ============================================================

    private fun forwardDns(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsPacket: ByteArray
    ) {

        var socket: DatagramSocket? = null

        try {

            socket =
                DatagramSocket()

            /*
             * VERY IMPORTANT:
             *
             * The upstream DNS socket must bypass
             * our VPN. Otherwise it can create a loop.
             */
            if (!protect(socket)) {

                android.util.Log.e(
                    TAG,
                    "protect(socket) failed"
                )

                return
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val request =
                DatagramPacket(
                    dnsPacket,
                    dnsPacket.size,
                    InetSocketAddress(
                        UPSTREAM_DNS,
                        DNS_PORT
                    )
                )

            socket.send(request)

            val buffer =
                ByteArray(
                    MAX_DNS_PACKET_SIZE
                )

            val responsePacket =
                DatagramPacket(
                    buffer,
                    buffer.size
                )

            socket.receive(
                responsePacket
            )

            if (responsePacket.length <= 0) {
                return
            }

            val response =
                responsePacket.data.copyOf(
                    responsePacket.length
                )

            /*
             * Protect against mismatched DNS responses.
             */
            if (
                dnsPacket.size >= 2 &&
                response.size >= 2
            ) {

                val queryId =
                    readU16(
                        dnsPacket,
                        0
                    )

                val responseId =
                    readU16(
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

            android.util.Log.w(
                TAG,
                "DNS forwarding failed",
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
            outputStream ?: return

        if (dnsResponse.isEmpty()) {
            return
        }

        if (
            originalLength <
            ipHeaderLength + UDP_HEADER_SIZE
        ) {
            return
        }

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
            UDP_HEADER_SIZE +
                dnsResponse.size

        val ipLength =
            IPV4_HEADER_SIZE +
                udpLength

        if (ipLength > 65535) {
            return
        }

        val responsePacket =
            ByteArray(ipLength)

        /*
         * IPv4 header.
         */
        responsePacket[0] =
            0x45.toByte()

        responsePacket[1] =
            0

        writeU16(
            responsePacket,
            2,
            ipLength
        )

        /*
         * Reuse packet identification.
         */
        responsePacket[4] =
            originalPacket[4]

        responsePacket[5] =
            originalPacket[5]

        /*
         * Don't fragment.
         */
        responsePacket[6] =
            0

        responsePacket[7] =
            0

        responsePacket[8] =
            64

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
         * Reverse addresses.
         *
         * Original:
         *
         * device -> DNS
         *
         * Response:
         *
         * DNS -> device
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

        val ipChecksum =
            checksum(
                responsePacket,
                0,
                IPV4_HEADER_SIZE
            )

        writeU16(
            responsePacket,
            10,
            ipChecksum
        )

        /*
         * UDP header.
         */
        writeU16(
            responsePacket,
            20,
            destinationPort
        )

        writeU16(
            responsePacket,
            22,
            sourcePort
        )

        writeU16(
            responsePacket,
            24,
            udpLength
        )

        /*
         * UDP checksum zero is valid for IPv4.
         */
        responsePacket[26] =
            0

        responsePacket[27] =
            0

        System.arraycopy(
            dnsResponse,
            0,
            responsePacket,
            IPV4_HEADER_SIZE +
                UDP_HEADER_SIZE,
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
                    "Could not write DNS response",
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
            scope.launch {

                /*
                 * Load filters immediately.
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
                 * Refresh periodically.
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
            "DNS: $dnsQueries  •  " +
                "Blocked: $blockedQueries  •  " +
                "Forwarded: $forwardedQueries"
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
                getString(
                    com.sathishkumarvasa.adblocker.R.string.app_name
                )
            )
            .setContentText(text)
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

    // ============================================================
    // CHECKSUM
    // ============================================================

    private fun checksum(
        data: ByteArray,
        offset: Int,
        length: Int
    ): Int {

        var sum = 0L

        var index = offset

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

            sum += word.toLong()

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

    private fun readU16(
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

    private fun writeU16(
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
    // STOP
    // ============================================================

    private fun stopVpn() {

        running.set(false)
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
         * Use the compatibility-safe API.
         *
         * This avoids the STOP_FOREGROUND_REMOVE
         * compilation problem you had earlier.
         */
        if (Build.VERSION.SDK_INT >= 24) {

            @Suppress("DEPRECATION")
            stopForeground(true)

        } else {

            @Suppress("DEPRECATION")
            stopForeground(true)
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

        scope.cancel()

        super.onDestroy()
    }

    override fun onBind(
        intent: Intent?
    ): IBinder? {

        return super.onBind(intent)
    }
}

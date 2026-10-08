package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
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

        private const val CHANNEL_ID =
            "ad_blocker_vpn"

        private const val NOTIFICATION_ID =
            1001

        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        private const val DNS_ADDRESS =
            "10.8.0.1"

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
        var isRunning =
            false
            private set
    }

    private var vpnInterface:
        ParcelFileDescriptor? =
        null

    private var inputStream:
        FileInputStream? =
        null

    private var outputStream:
        FileOutputStream? =
        null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )

    private var packetJob:
        Job? =
        null

    private var filterRefreshJob:
        Job? =
        null

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

        return START_NOT_STICKY
    }

    private fun startVpn() {

        if (running.get()) {
            updateDiagnosticNotification()
            return
        }

        dnsQueryCount = 0
        blockedDnsCount = 0
        forwardedDnsCount = 0

        try {

            startForegroundServiceNotification(
                "Starting VPN..."
            )

            val builder =
                Builder()
                    .setSession(
                        getString(
                            R.string.app_name
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
             * Do not route this application's own
             * traffic through the VPN.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (error: Exception) {

                android.util.Log.w(
                    "AdBlockVpnService",
                    "Could not exclude own application",
                    error
                )
            }

            val established =
                builder.establish()

            if (established == null) {

                updateNotification(
                    "VPN could not be established"
                )

                stopVpn()

                return
            }

            vpnInterface =
                established

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

            updateDiagnosticNotification()

            startPacketLoop()

            startFilterRefreshLoop()

            android.util.Log.i(
                "AdBlockVpnService",
                "VPN started successfully"
            )

        } catch (error: Exception) {

            android.util.Log.e(
                "AdBlockVpnService",
                "VPN start failed",
                error
            )

            updateNotification(
                "VPN error: ${error.message}"
            )

            stopVpn()
        }
    }

    private fun startForegroundServiceNotification(
        text: String
    ) {

        val notification =
            createNotification(text)

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.Q
        ) {

            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )

        } else {

            startForeground(
                NOTIFICATION_ID,
                notification
            )
        }
    }

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

                        processIpv4Packet(packet)

                    } catch (error: Exception) {

                        if (running.get()) {

                            android.util.Log.w(
                                "AdBlockVpnService",
                                "Packet read failed",
                                error
                            )
                        }

                        break
                    }
                }
            }
    }

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
                packet[0].toInt() ushr 4
            ) and 0x0F

        if (version != 4) {
            return
        }

        val ipHeaderLength =
            (
                packet[0].toInt() and 0x0F
            ) * 4

        if (
            ipHeaderLength <
            IPV4_HEADER_LENGTH ||
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

        if (protocol != UDP_PROTOCOL) {
            return
        }

        processUdpPacket(
            packet,
            totalLength,
            ipHeaderLength
        )
    }

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
            udpLength <
            UDP_HEADER_LENGTH
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
         * Only DNS queries.
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

    private fun handleDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        dnsQueryCount++

        updateDiagnosticNotification()

        val hostname =
            parseDnsQuestionName(dnsQuery)

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

            return
        }

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase()

        android.util.Log.d(
            "AdBlockVpnService",
            "DNS: $normalized"
        )

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

        val blocked =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (error: Exception) {

                android.util.Log.e(
                    "AdBlockVpnService",
                    "Filter error",
                    error
                )

                false
            }

        if (blocked) {

            blockedDnsCount++

            try {
                AdBlockStorage.incrementBlockedCount(this)
            } catch (_: Exception) {
            }

            val response =
                buildBlockedDnsResponse(
                    dnsQuery
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

            android.util.Log.d(
                "AdBlockVpnService",
                "BLOCKED: $normalized"
            )

        } else {

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

        updateDiagnosticNotification()
    }

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
                            .lowercase()
                    }
                    .toSet()
            } catch (_: Exception) {
                emptySet()
            }

        if (
            allowlist.contains(hostname)
        ) {
            return true
        }

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

    private fun parseDnsQuestionName(
        dnsPacket: ByteArray
    ): String? {

        if (
            dnsPacket.size <
            DNS_HEADER_LENGTH + 1
        ) {
            return null
        }

        val questionCount =
            readUnsignedShort(
                dnsPacket,
                4
            )

        if (questionCount <= 0) {
            return null
        }

        var position =
            DNS_HEADER_LENGTH

        val labels =
            mutableListOf<String>()

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
             * DNS compression is not expected in the
             * question section.
             */
            if (
                (length and 0xC0) != 0
            ) {
                return null
            }

            if (
                length > 63 ||
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

            labels.add(label)

            position += length
        }

        if (labels.isEmpty()) {
            return null
        }

        return labels
            .joinToString(".")
            .lowercase()
    }

    private fun buildBlockedDnsResponse(
        query: ByteArray
    ): ByteArray? {

        if (
            query.size <
            DNS_HEADER_LENGTH
        ) {
            return null
        }

        val response =
            query.copyOf()

        val originalFlags =
            readUnsignedShort(
                query,
                2
            )

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
         * RA.
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

        writeUnsignedShort(
            response,
            4,
            1
        )

        writeUnsignedShort(
            response,
            6,
            0
        )

        writeUnsignedShort(
            response,
            8,
            0
        )

        writeUnsignedShort(
            response,
            10,
            0
        )

        return response
    }

    private fun forwardDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray
    ) {

        var socket:
            DatagramSocket? =
            null

        try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL:
             * The upstream DNS socket must bypass
             * our VPN or we create a DNS loop.
             */
            if (!protect(socket)) {

                android.util.Log.e(
                    "AdBlockVpnService",
                    "Could not protect DNS socket"
                )

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

            socket.receive(responsePacket)

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

                if (queryId != responseId) {

                    android.util.Log.w(
                        "AdBlockVpnService",
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

        } catch (error: Exception) {

            android.util.Log.w(
                "AdBlockVpnService",
                "DNS forwarding failed",
                error
            )

        } finally {

            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

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

        if (
            originalPacket.size <
            IPV4_HEADER_LENGTH
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
            UDP_HEADER_LENGTH +
                dnsResponse.size

        val ipLength =
            IPV4_HEADER_LENGTH +
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

        writeUnsignedShort(
            responsePacket,
            2,
            ipLength
        )

        responsePacket[4] =
            originalPacket[4]

        responsePacket[5] =
            originalPacket[5]

        responsePacket[6] =
            0

        responsePacket[7] =
            0

        responsePacket[8] =
            64

        responsePacket[9] =
            UDP_PROTOCOL.toByte()

        responsePacket[10] =
            0

        responsePacket[11] =
            0

        /*
         * Reverse source/destination addresses.
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

        /*
         * UDP header.
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
         * IPv4 permits UDP checksum zero.
         */
        responsePacket[26] =
            0

        responsePacket[27] =
            0

        /*
         * DNS payload.
         */
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

        } catch (error: Exception) {

            if (running.get()) {

                android.util.Log.w(
                    "AdBlockVpnService",
                    "Could not write DNS response",
                    error
                )
            }
        }
    }

    private fun updateDiagnosticNotification() {

        if (!running.get()) {
            return
        }

        updateNotification(
            "DNS: $dnsQueryCount • " +
                "Blocked: $blockedDnsCount • " +
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

        } catch (error: Exception) {

            android.util.Log.w(
                "AdBlockVpnService",
                "Notification update failed",
                error
            )
        }
    }

    private fun startFilterRefreshLoop() {

        filterRefreshJob?.cancel()

        filterRefreshJob =
            serviceScope.launch {

                try {

                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )

                } catch (error: Exception) {

                    android.util.Log.w(
                        "AdBlockVpnService",
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

                    if (!running.get()) {
                        break
                    }

                    try {

                        FilterManager.updateFilters(
                            this@AdBlockVpnService
                        )

                    } catch (error: Exception) {

                        android.util.Log.w(
                            "AdBlockVpnService",
                            "Filter refresh failed",
                            error
                        )
                    }
                }
            }
    }

    private fun stopVpn() {

        running.set(false)

        isRunning = false

        packetJob?.cancel()
        packetJob = null

        filterRefreshJob?.cancel()
        filterRefreshJob = null

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

        val interfaceToClose =
            vpnInterface

        vpnInterface = null

        try {
            interfaceToClose?.close()
        } catch (_: Exception) {
        }

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.N
        ) {

            stopForeground(
                STOP_FOREGROUND_REMOVE
            )

        } else {

            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        stopSelf()
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
                    R.string.app_name
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

    private fun calculateChecksum(
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

        return super.onBind(intent)
    }
}

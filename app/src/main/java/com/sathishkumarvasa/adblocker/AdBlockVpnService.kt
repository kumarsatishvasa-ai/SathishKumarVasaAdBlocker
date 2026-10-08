package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
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
         * VPN interface address.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        /*
         * DNS address presented to Android.
         *
         * Only packets destined for this address are routed
         * into this VPN.
         */
        private const val DNS_ADDRESS =
            "10.8.0.1"

        private const val VPN_PREFIX =
            24

        /*
         * Public upstream DNS.
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
            3500

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

    @Volatile
    private var failedQueries = 0

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
    // START
    // ============================================================

    private fun startVpn() {

        if (running.get()) {
            return
        }

        resetCounters()

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
             * We DO NOT use:
             *
             *     0.0.0.0/0
             *
             * Therefore normal application traffic such as:
             *
             * Chrome HTTPS
             * YouTube HTTPS
             * Google Search HTTPS
             * Play Store HTTPS
             *
             * is NOT routed through this VPN.
             *
             * Only traffic to DNS_ADDRESS enters the VPN.
             */
            val builder =
                Builder()
                    .setSession(
                        applicationInfo
                            .loadLabel(packageManager)
                            .toString()
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
             * The blocker itself must bypass its own VPN.
             *
             * This is especially important when forwarding DNS
             * to 1.1.1.1.
             */
            try {

                builder.addDisallowedApplication(
                    packageName
                )

            } catch (e: Exception) {

                Log.w(
                    TAG,
                    "Could not exclude own application",
                    e
                )
            }

            val descriptor =
                builder.establish()

            if (descriptor == null) {

                Log.e(
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
                descriptor

            inputStream =
                FileInputStream(
                    descriptor.fileDescriptor
                )

            outputStream =
                FileOutputStream(
                    descriptor.fileDescriptor
                )

            running.set(true)

            isRunning = true

            startPacketLoop()

            startFilterRefresh()

            updateNotification(
                "DNS protection active"
            )

            Log.i(
                TAG,
                "DNS VPN started"
            )

        } catch (e: Exception) {

            Log.e(
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
                    ByteArray(MAX_PACKET_SIZE)

                while (
                    isActive &&
                    running.get()
                ) {

                    val input =
                        inputStream ?: break

                    try {

                        val length =
                            input.read(buffer)

                        if (length <= 0) {
                            continue
                        }

                        processPacket(
                            buffer.copyOf(length)
                        )

                    } catch (e: Exception) {

                        if (running.get()) {

                            Log.w(
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
            packet.size <
            IPV4_HEADER_LENGTH
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
            headerLength < IPV4_HEADER_LENGTH ||
            headerLength > packet.size
        ) {
            return
        }

        val totalLength =
            readUnsignedShort(
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
         * Only UDP is relevant to this simple DNS proxy.
         *
         * TCP/HTTPS traffic is intentionally ignored.
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

        /*
         * We only handle DNS requests.
         */
        if (destinationPort != DNS_PORT) {
            return
        }

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

        val dnsOffset =
            udpOffset + UDP_HEADER_LENGTH

        val dnsLength =
            udpLength - UDP_HEADER_LENGTH

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
        dnsPacket: ByteArray
    ) {

        dnsQueries++

        /*
         * Parse ONLY the first question hostname.
         *
         * If anything looks unusual, fail open and forward it.
         */
        val hostname =
            parseDnsHostname(
                dnsPacket
            )

        if (hostname == null) {

            forwardedQueries++

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                dnsPacket
            )

            updateNotificationCounters()

            return
        }

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (normalized.isEmpty()) {

            forwardedQueries++

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                dnsPacket
            )

            updateNotificationCounters()

            return
        }

        /*
         * The filter manager is the ONLY blocking decision.
         */
        val shouldBlock =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (e: Exception) {

                /*
                 * VERY IMPORTANT:
                 *
                 * If FilterManager crashes or has a problem,
                 * fail open rather than breaking Chrome/YouTube.
                 */
                Log.e(
                    TAG,
                    "FilterManager error; allowing $normalized",
                    e
                )

                false
            }

        if (shouldBlock) {

            blockedQueries++

            Log.d(
                TAG,
                "BLOCKED $normalized"
            )

            try {

                AdBlockStorage.incrementBlockedCount(
                    this
                )

            } catch (_: Exception) {
            }

            val blockedResponse =
                createBlockedResponse(
                    dnsPacket
                )

            if (blockedResponse != null) {

                writeDnsResponse(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    blockedResponse
                )

            } else {

                /*
                 * Never break DNS just because we couldn't build
                 * a blocking response.
                 */
                forwardedQueries++

                forwardDns(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    dnsPacket
                )
            }

        } else {

            forwardedQueries++

            Log.d(
                TAG,
                "ALLOW $normalized"
            )

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                dnsPacket
            )
        }

        updateNotificationCounters()
    }

    // ============================================================
    // DNS NAME PARSER
    // ============================================================

    private fun parseDnsHostname(
        packet: ByteArray
    ): String? {

        if (
            packet.size <
            DNS_HEADER_LENGTH + 1
        ) {
            return null
        }

        val flags =
            readUnsignedShort(
                packet,
                2
            )

        /*
         * QR=1 means response.
         */
        if (
            flags and 0x8000 != 0
        ) {
            return null
        }

        val questions =
            readUnsignedShort(
                packet,
                4
            )

        if (questions <= 0) {
            return null
        }

        var position =
            DNS_HEADER_LENGTH

        val labels =
            ArrayList<String>()

        while (
            position < packet.size
        ) {

            val length =
                packet[position]
                    .toInt() and 0xFF

            position++

            /*
             * End of DNS name.
             */
            if (length == 0) {
                break
            }

            /*
             * Compression in a question name is unusual.
             * Fail open rather than guessing.
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
                packet.size
            ) {
                return null
            }

            val label =
                packet
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
             * DNS hostname validation.
             *
             * Underscores are accepted because SRV/service-related
             * DNS names exist and must not be accidentally dropped.
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
    // BLOCK RESPONSE
    // ============================================================

    private fun createBlockedResponse(
        query: ByteArray
    ): ByteArray? {

        if (
            query.size <
            DNS_HEADER_LENGTH
        ) {
            return null
        }

        /*
         * Keep the original question and transaction ID.
         */
        val response =
            query.copyOf()

        val queryFlags =
            readUnsignedShort(
                query,
                2
            )

        /*
         * QR = response
         * RD = preserve requested recursion
         * RA = recursion available
         * RCODE = NXDOMAIN
         */
        var flags =
            0x8000

        if (
            queryFlags and 0x0100 != 0
        ) {
            flags =
                flags or 0x0100
        }

        flags =
            flags or 0x0080

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
    // UPSTREAM DNS
    // ============================================================

    private fun forwardDns(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        dnsQuery: ByteArray
    ) {

        var socket: DatagramSocket? = null

        try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL:
             *
             * The upstream DNS socket must bypass the VPN.
             *
             * Otherwise:
             *
             * VPN -> DNS proxy -> 1.1.1.1
             *
             * can become:
             *
             * VPN -> VPN -> VPN -> ...
             */
            if (!protect(socket)) {

                failedQueries++

                Log.e(
                    TAG,
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

            socket.receive(
                responsePacket
            )

            if (
                responsePacket.length <= 0
            ) {

                failedQueries++

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
                !sameTransactionId(
                    dnsQuery,
                    response
                )
            ) {

                failedQueries++

                Log.w(
                    TAG,
                    "Ignoring DNS response with wrong transaction ID"
                )

                return
            }

            writeDnsResponse(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                response
            )

        } catch (e: Exception) {

            failedQueries++

            /*
             * We deliberately don't crash the VPN.
             */
            Log.w(
                TAG,
                "Upstream DNS request failed",
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
    // TRANSACTION ID
    // ============================================================

    private fun sameTransactionId(
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
    // WRITE DNS RESPONSE
    // ============================================================

    private fun writeDnsResponse(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        dnsResponse: ByteArray
    ) {

        val output =
            outputStream ?: return

        if (dnsResponse.isEmpty()) {
            return
        }

        if (
            originalPacket.size < 20
        ) {
            return
        }

        if (
            originalLength <
            ipHeaderLength + UDP_HEADER_LENGTH
        ) {
            return
        }

        /*
         * Original:
         *
         * source = application
         * destination = 10.8.0.1
         *
         * Response:
         *
         * source = 10.8.0.1
         * destination = application
         */
        val originalSource =
            originalPacket.copyOfRange(
                12,
                16
            )

        val originalDestination =
            originalPacket.copyOfRange(
                16,
                20
            )

        val udpLength =
            UDP_HEADER_LENGTH +
                dnsResponse.size

        val totalLength =
            IPV4_HEADER_LENGTH +
                udpLength

        if (
            totalLength > 65535
        ) {
            return
        }

        val packet =
            ByteArray(totalLength)

        /*
         * --------------------------------------------------------
         * IPv4 HEADER
         * --------------------------------------------------------
         */

        packet[0] =
            0x45.toByte()

        packet[1] =
            0

        writeUnsignedShort(
            packet,
            2,
            totalLength
        )

        /*
         * Reuse identification.
         */
        if (
            originalPacket.size >= 6
        ) {

            packet[4] =
                originalPacket[4]

            packet[5] =
                originalPacket[5]
        }

        /*
         * Don't fragment.
         */
        packet[6] =
            0

        packet[7] =
            0

        packet[8] =
            64

        packet[9] =
            UDP_PROTOCOL.toByte()

        /*
         * Source = original destination.
         */
        System.arraycopy(
            originalDestination,
            0,
            packet,
            12,
            4
        )

        /*
         * Destination = original source.
         */
        System.arraycopy(
            originalSource,
            0,
            packet,
            16,
            4
        )

        /*
         * Calculate IPv4 checksum.
         */
        packet[10] =
            0

        packet[11] =
            0

        val ipChecksum =
            checksum(
                packet,
                0,
                IPV4_HEADER_LENGTH
            )

        writeUnsignedShort(
            packet,
            10,
            ipChecksum
        )

        /*
         * --------------------------------------------------------
         * UDP HEADER
         * --------------------------------------------------------
         */

        /*
         * Source port = DNS 53.
         */
        writeUnsignedShort(
            packet,
            20,
            DNS_PORT
        )

        /*
         * Destination port = application port.
         */
        writeUnsignedShort(
            packet,
            22,
            sourcePort
        )

        writeUnsignedShort(
            packet,
            24,
            udpLength
        )

        /*
         * UDP checksum zero is valid for IPv4.
         */
        packet[26] =
            0

        packet[27] =
            0

        /*
         * --------------------------------------------------------
         * DNS PAYLOAD
         * --------------------------------------------------------
         */

        System.arraycopy(
            dnsResponse,
            0,
            packet,
            IPV4_HEADER_LENGTH +
                UDP_HEADER_LENGTH,
            dnsResponse.size
        )

        try {

            output.write(packet)

            output.flush()

        } catch (e: Exception) {

            if (running.get()) {

                Log.w(
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
            serviceScope.launch {

                /*
                 * Initial update.
                 *
                 * If it fails, the existing FilterManager
                 * database remains intact.
                 */
                try {

                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )

                } catch (e: Exception) {

                    Log.w(
                        TAG,
                        "Initial filter update failed",
                        e
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

                        Log.w(
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

    private fun updateNotificationCounters() {

        if (!running.get()) {
            return
        }

        updateNotification(
            "DNS $dnsQueries • " +
                "Blocked $blockedQueries • " +
                "Allowed $forwardedQueries"
        )
    }

    private fun updateNotification(
        message: String
    ) {

        try {

            val manager =
                getSystemService(
                    NotificationManager::class.java
                )

            manager.notify(
                NOTIFICATION_ID,
                createNotification(message)
            )

        } catch (e: Exception) {

            Log.w(
                TAG,
                "Could not update notification",
                e
            )
        }
    }

    private fun createNotification(
        message: String
    ): Notification {

        val appName =
            applicationInfo
                .loadLabel(packageManager)
                .toString()

        return NotificationCompat
            .Builder(
                this,
                CHANNEL_ID
            )
            .setSmallIcon(
                android.R.drawable.stat_sys_warning
            )
            .setContentTitle(
                appName
            )
            .setContentText(
                message
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

    private fun checksum(
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
    // RESET
    // ============================================================

    private fun resetCounters() {

        dnsQueries = 0
        blockedQueries = 0
        forwardedQueries = 0
        failedQueries = 0
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

        try {

            @Suppress("DEPRECATION")
            stopForeground(true)

        } catch (_: Exception) {
        }

        stopSelf()

        Log.i(
            TAG,
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
}

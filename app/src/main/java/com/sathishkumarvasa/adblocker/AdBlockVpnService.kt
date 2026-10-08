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
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockVpnService : VpnService() {

    companion object {
        const val ACTION_START =
            "com.sathishkumarvasa.adblocker.START"

        const val ACTION_STOP =
            "com.sathishkumarvasa.adblocker.STOP"

        private const val TAG = "AdBlockVpnService"

        private const val CHANNEL_ID = "ad_blocker_vpn"
        private const val NOTIFICATION_ID = 1001

        /*
         * VPN interface address.
         */
        private const val VPN_ADDRESS = "10.8.0.2"

        /*
         * DNS address presented to Android.
         */
        private const val DNS_ADDRESS = "10.8.0.1"

        private const val VPN_PREFIX = 24

        /*
         * Cloudflare IPv4 DNS.
         *
         * The socket used for this connection is protected
         * before sending anything.
         */
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val DNS_PORT = 53

        private const val MTU = 1500

        private const val READ_BUFFER_SIZE = 32767
        private const val DNS_BUFFER_SIZE = 4096

        private const val DNS_TIMEOUT_MS = 4000

        private const val IPV4_HEADER_MIN = 20
        private const val UDP_HEADER_SIZE = 8
        private const val DNS_HEADER_SIZE = 12

        private const val UDP_PROTOCOL = 17

        private const val FILTER_REFRESH_MS =
            12L * 60L * 60L * 1000L

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO
        )

    private val running =
        AtomicBoolean(false)

    private var vpnInterface: ParcelFileDescriptor? = null

    private var inputStream: FileInputStream? = null

    private var outputStream: FileOutputStream? = null

    private var packetJob: Job? = null

    private var filterJob: Job? = null

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

        dnsQueries = 0
        blockedQueries = 0
        forwardedQueries = 0
        failedQueries = 0

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
             * We deliberately DO NOT add:
             *
             * addRoute("0.0.0.0", 0)
             *
             * Therefore this VPN is not a general traffic tunnel.
             *
             * The only routed address is our local DNS endpoint.
             *
             * Normal HTTPS traffic from Chrome and YouTube remains
             * on Android's ordinary network path.
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
             * Never route our own application traffic through
             * the VPN.
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

            val descriptor =
                builder.establish()

            if (descriptor == null) {

                updateNotification(
                    "Could not establish VPN"
                )

                stopVpn()
                return
            }

            vpnInterface = descriptor

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

            updateNotification(
                "DNS protection active"
            )

            startPacketLoop()
            startFilterRefresh()

            android.util.Log.i(
                TAG,
                "VPN started"
            )

        } catch (e: Exception) {

            android.util.Log.e(
                TAG,
                "Could not start VPN",
                e
            )

            updateNotification(
                "VPN start failed"
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
                        READ_BUFFER_SIZE
                    )

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
                            buffer,
                            count
                        )

                    } catch (e: Exception) {

                        if (running.get()) {

                            android.util.Log.w(
                                TAG,
                                "VPN read error",
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
        buffer: ByteArray,
        packetLength: Int
    ) {

        if (
            packetLength <
            IPV4_HEADER_MIN
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
            headerLength < IPV4_HEADER_MIN ||
            headerLength > packetLength
        ) {
            return
        }

        val totalLength =
            readU16(
                buffer,
                2
            )

        if (
            totalLength < headerLength ||
            totalLength > packetLength
        ) {
            return
        }

        val protocol =
            buffer[9].toInt() and 0xFF

        /*
         * Only UDP.
         *
         * TCP/HTTPS is deliberately ignored.
         */
        if (
            protocol != UDP_PROTOCOL
        ) {
            return
        }

        processUdp(
            buffer,
            totalLength,
            headerLength
        )
    }

    // ============================================================
    // UDP DNS
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
            udpOffset + udpLength >
            totalLength
        ) {
            return
        }

        /*
         * We only handle DNS queries.
         */
        if (
            destinationPort != DNS_PORT
        ) {
            return
        }

        val dnsOffset =
            udpOffset + UDP_HEADER_SIZE

        val dnsLength =
            udpLength - UDP_HEADER_SIZE

        if (
            dnsLength < DNS_HEADER_SIZE
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
        dnsQuery: ByteArray
    ) {

        dnsQueries++

        val hostname =
            parseHostname(
                dnsQuery
            )

        /*
         * If parsing fails, fail OPEN.
         *
         * We forward the original DNS packet rather than
         * blocking it.
         */
        if (hostname == null) {

            forwardedQueries++

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                dnsQuery
            )

            updateNotificationStats()
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
                dnsQuery
            )

            updateNotificationStats()
            return
        }

        android.util.Log.d(
            TAG,
            "DNS: $normalized"
        )

        val blocked =
            try {

                FilterManager.isBlockedHost(
                    this,
                    normalized
                )

            } catch (e: Exception) {

                /*
                 * Filter errors must NEVER break DNS.
                 */
                android.util.Log.e(
                    TAG,
                    "FilterManager error",
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
                "BLOCK: $normalized"
            )

            val response =
                createBlockedResponse(
                    dnsQuery
                )

            if (response != null) {

                writeDnsResponse(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    response
                )

            } else {

                /*
                 * Fail open if the block response cannot be
                 * constructed.
                 */
                forwardedQueries++

                forwardDns(
                    originalPacket,
                    originalLength,
                    ipHeaderLength,
                    sourcePort,
                    dnsQuery
                )
            }

        } else {

            forwardedQueries++

            forwardDns(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                dnsQuery
            )
        }

        updateNotificationStats()
    }

    // ============================================================
    // DNS HOSTNAME PARSER
    // ============================================================

    private fun parseHostname(
        dns: ByteArray
    ): String? {

        if (
            dns.size <
            DNS_HEADER_SIZE + 1
        ) {
            return null
        }

        val flags =
            readU16(
                dns,
                2
            )

        /*
         * Ignore DNS responses.
         */
        if (
            flags and 0x8000 != 0
        ) {
            return null
        }

        val questionCount =
            readU16(
                dns,
                4
            )

        if (
            questionCount <= 0
        ) {
            return null
        }

        var position =
            DNS_HEADER_SIZE

        val labels =
            ArrayList<String>()

        while (
            position < dns.size
        ) {

            val length =
                dns[position]
                    .toInt() and 0xFF

            position++

            if (length == 0) {
                break
            }

            /*
             * Compression pointer in the question section.
             * We fail open instead of guessing.
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
                dns.size
            ) {
                return null
            }

            val label =
                dns.copyOfRange(
                    position,
                    position + length
                ).toString(
                    Charsets.US_ASCII
                )

            if (label.isEmpty()) {
                return null
            }

            /*
             * Hostname validation.
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

            if (
                labels.size > 127
            ) {
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

    private fun createBlockedResponse(
        query: ByteArray
    ): ByteArray? {

        if (
            query.size <
            DNS_HEADER_SIZE
        ) {
            return null
        }

        val response =
            query.copyOf()

        val queryFlags =
            readU16(
                query,
                2
            )

        /*
         * QR = response
         * RD = preserved
         * RA = 1
         * RCODE = NXDOMAIN
         */
        var flags = 0x8000

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

        writeU16(
            response,
            2,
            flags
        )

        /*
         * One question.
         */
        writeU16(
            response,
            4,
            1
        )

        /*
         * No answers.
         */
        writeU16(
            response,
            6,
            0
        )

        /*
         * No authority records.
         */
        writeU16(
            response,
            8,
            0
        )

        /*
         * No additional records.
         */
        writeU16(
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
        query: ByteArray
    ) {

        var socket: DatagramSocket? = null

        try {

            socket =
                DatagramSocket()

            /*
             * CRITICAL:
             *
             * This prevents the upstream DNS request from being
             * captured by our own VPN route.
             */
            if (!protect(socket)) {

                failedQueries++

                android.util.Log.e(
                    TAG,
                    "Could not protect DNS socket"
                )

                return
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val server =
                InetAddress.getByName(
                    UPSTREAM_DNS
                )

            val request =
                DatagramPacket(
                    query,
                    query.size,
                    server,
                    DNS_PORT
                )

            socket.send(request)

            val buffer =
                ByteArray(
                    DNS_BUFFER_SIZE
                )

            val responsePacket =
                DatagramPacket(
                    buffer,
                    buffer.size
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
             * Validate DNS transaction ID.
             */
            if (
                query.size >= 2 &&
                response.size >= 2
            ) {

                val queryId =
                    readU16(
                        query,
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

                    failedQueries++

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
                response
            )

        } catch (e: Exception) {

            failedQueries++

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
    // WRITE RESPONSE
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

        val totalLength =
            20 +
                udpLength

        if (
            totalLength > 65535
        ) {
            return
        }

        val response =
            ByteArray(
                totalLength
            )

        /*
         * IPv4 header.
         */
        response[0] =
            0x45.toByte()

        response[1] = 0

        writeU16(
            response,
            2,
            totalLength
        )

        /*
         * Reuse packet identification.
         */
        if (
            originalPacket.size >= 6
        ) {
            response[4] =
                originalPacket[4]

            response[5] =
                originalPacket[5]
        }

        response[6] = 0
        response[7] = 0

        response[8] = 64

        response[9] =
            UDP_PROTOCOL.toByte()

        /*
         * Reverse source/destination.
         */
        System.arraycopy(
            destinationIp,
            0,
            response,
            12,
            4
        )

        System.arraycopy(
            sourceIp,
            0,
            response,
            16,
            4
        )

        /*
         * IPv4 checksum.
         */
        response[10] = 0
        response[11] = 0

        val checksum =
            ipv4Checksum(
                response,
                0,
                20
            )

        writeU16(
            response,
            10,
            checksum
        )

        /*
         * UDP.
         *
         * Source = DNS port.
         * Destination = original client port.
         */
        writeU16(
            response,
            20,
            DNS_PORT
        )

        writeU16(
            response,
            22,
            sourcePort
        )

        writeU16(
            response,
            24,
            udpLength
        )

        /*
         * UDP checksum 0 is valid for IPv4.
         */
        response[26] = 0
        response[27] = 0

        System.arraycopy(
            dnsResponse,
            0,
            response,
            28,
            dnsResponse.size
        )

        try {

            output.write(response)
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
            serviceScope.launch {

                /*
                 * Filter download is never allowed to block
                 * DNS packet processing.
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

    private fun updateNotificationStats() {

        if (!running.get()) {
            return
        }

        updateNotification(
            "DNS $dnsQueries • " +
                "Blocked $blockedQueries • " +
                "Forwarded $forwardedQueries"
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

            android.util.Log.w(
                TAG,
                "Notification failed",
                e
            )
        }
    }

    private fun createNotification(
        message: String
    ): Notification {

        val title =
            applicationInfo
                .loadLabel(packageManager)
                .toString()

        return NotificationCompat
            .Builder(
                this,
                CHANNEL_ID
            )
            .setContentTitle(title)
            .setContentText(message)
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

    // ============================================================
    // CHECKSUM
    // ============================================================

    private fun ipv4Checksum(
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

            sum +=
                (
                    ((data[index].toInt() and 0xFF) shl 8) or
                        (data[index + 1].toInt() and 0xFF)
                    ).toLong()

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

        try {

            @Suppress("DEPRECATION")
            stopForeground(true)

        } catch (_: Exception) {
        }

        stopSelf()
    }

    // ============================================================
    // REVOKE
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

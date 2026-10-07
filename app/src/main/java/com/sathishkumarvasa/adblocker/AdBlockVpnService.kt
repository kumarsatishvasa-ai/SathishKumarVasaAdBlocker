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

        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val VPN_PREFIX =
            24

        private const val VPN_DNS_ADDRESS =
            "10.8.0.1"

        private const val UPSTREAM_DNS =
            "1.1.1.1"

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

        private const val MAX_PACKET_SIZE =
            32767

        private const val MAX_DNS_SIZE =
            4096

        private const val DNS_TIMEOUT_MS =
            3000

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    private var packetJob: Job? = null

    private var filterRefreshJob: Job? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO
        )

    private val running =
        AtomicBoolean(false)

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

            ACTION_START,
            null -> {
                startVpn()
            }

            else -> {
                startVpn()
            }
        }

        return START_STICKY
    }

    private fun startVpn() {

        if (running.get()) {
            return
        }

        if (!AdBlockStorage.isEnabled(this)) {
            stopSelf()
            return
        }

        try {

            val builder =
                Builder()
                    .setSession(
                        getString(R.string.app_name)
                    )
                    .setMtu(MTU)
                    .addAddress(
                        VPN_ADDRESS,
                        VPN_PREFIX
                    )
                    .addRoute(
                        "0.0.0.0",
                        0
                    )
                    .addDnsServer(
                        VPN_DNS_ADDRESS
                    )

            /*
             * Do not capture this application's own traffic.
             * This prevents our upstream DNS socket from entering
             * the VPN again.
             */
            try {
                builder.addDisallowedApplication(
                    packageName
                )
            } catch (error: Exception) {
                android.util.Log.w(
                    TAG,
                    "Could not exclude own package from VPN",
                    error
                )
            }

            val established =
                builder.establish()

            if (established == null) {

                android.util.Log.e(
                    TAG,
                    "VPN establish() returned null"
                )

                stopVpn()
                return
            }

            vpnInterface =
                established

            running.set(true)
            isRunning = true

            startForeground(
                NOTIFICATION_ID,
                createNotification()
            )

            startPacketLoop()
            startFilterRefreshLoop()

            android.util.Log.i(
                TAG,
                "VPN started"
            )

        } catch (error: Exception) {

            android.util.Log.e(
                TAG,
                "Unable to start VPN",
                error
            )

            stopVpn()
        }
    }

    private fun startPacketLoop() {

        packetJob?.cancel()

        packetJob =
            serviceScope.launch {

                val descriptor =
                    vpnInterface
                        ?: return@launch

                val input =
                    try {
                        FileInputStream(
                            descriptor.fileDescriptor
                        )
                    } catch (error: Exception) {

                        android.util.Log.e(
                            TAG,
                            "Could not open VPN input",
                            error
                        )

                        return@launch
                    }

                val output =
                    try {
                        FileOutputStream(
                            descriptor.fileDescriptor
                        )
                    } catch (error: Exception) {

                        android.util.Log.e(
                            TAG,
                            "Could not open VPN output",
                            error
                        )

                        try {
                            input.close()
                        } catch (_: Exception) {
                        }

                        return@launch
                    }

                val buffer =
                    ByteArray(
                        MAX_PACKET_SIZE
                    )

                try {

                    while (
                        isActive &&
                        running.get()
                    ) {

                        val count =
                            try {
                                input.read(buffer)
                            } catch (error: Exception) {

                                if (running.get()) {
                                    android.util.Log.e(
                                        TAG,
                                        "VPN packet read failed",
                                        error
                                    )
                                }

                                break
                            }

                        if (count <= 0) {
                            continue
                        }

                        val packet =
                            buffer.copyOf(count)

                        processPacket(
                            packet,
                            output
                        )
                    }

                } finally {

                    try {
                        input.close()
                    } catch (_: Exception) {
                    }

                    try {
                        output.close()
                    } catch (_: Exception) {
                    }
                }
            }
    }

    private fun processPacket(
        packet: ByteArray,
        output: FileOutputStream
    ) {

        if (packet.size < IPV4_HEADER_LENGTH) {
            return
        }

        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ipHeaderLength < IPV4_HEADER_LENGTH ||
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
         * This implementation intentionally handles DNS UDP.
         * Other traffic is not forwarded by this lightweight
         * DNS-only VPN.
         */
        if (protocol != 17) {
            return
        }

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
            udpLength < UDP_HEADER_LENGTH ||
            udpOffset + udpLength > totalLength
        ) {
            return
        }

        /*
         * Only intercept DNS queries.
         */
        if (destinationPort != DNS_PORT) {
            return
        }

        val dnsOffset =
            udpOffset + UDP_HEADER_LENGTH

        val dnsLength =
            udpLength - UDP_HEADER_LENGTH

        if (dnsLength < DNS_HEADER_LENGTH) {
            return
        }

        if (
            dnsOffset + dnsLength > totalLength
        ) {
            return
        }

        val dnsQuery =
            packet.copyOfRange(
                dnsOffset,
                dnsOffset + dnsLength
            )

        processDnsQuery(
            originalPacket = packet,
            originalLength = totalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsQuery = dnsQuery,
            output = output
        )
    }

    private fun processDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray,
        output: FileOutputStream
    ) {

        val hostname =
            parseDnsQuestionName(
                dnsQuery
            )

        if (hostname == null) {
            return
        }

        android.util.Log.d(
            TAG,
            "DNS query: $hostname"
        )

        if (
            AdBlockStorage.isDomainAllowlisted(
                this,
                hostname
            )
        ) {

            forwardDnsQuery(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                dnsQuery,
                output
            )

            return
        }

        val blocked =
            FilterManager.isBlockedHost(
                this,
                hostname
            )

        if (blocked) {

            android.util.Log.d(
                TAG,
                "Blocked: $hostname"
            )

            AdBlockStorage.incrementBlockedCount(
                this
            )

            val response =
                buildBlockedDnsResponse(
                    dnsQuery
                )

            writeDnsResponse(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                response,
                output
            )

            return
        }

        forwardDnsQuery(
            originalPacket,
            originalLength,
            ipHeaderLength,
            sourcePort,
            destinationPort,
            dnsQuery,
            output
        )
    }

    private fun forwardDnsQuery(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsQuery: ByteArray,
        output: FileOutputStream
    ) {

        val socket =
            DatagramSocket()

        try {

            if (!protect(socket)) {

                android.util.Log.e(
                    TAG,
                    "Could not protect upstream DNS socket"
                )

                return
            }

            socket.soTimeout =
                DNS_TIMEOUT_MS

            val server =
                InetSocketAddress(
                    UPSTREAM_DNS,
                    DNS_PORT
                )

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    server
                )

            socket.send(request)

            val responseBuffer =
                ByteArray(
                    MAX_DNS_SIZE
                )

            val responsePacket =
                DatagramPacket(
                    responseBuffer,
                    responseBuffer.size
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

            writeDnsResponse(
                originalPacket,
                originalLength,
                ipHeaderLength,
                sourcePort,
                destinationPort,
                response,
                output
            )

        } catch (error: Exception) {

            android.util.Log.w(
                TAG,
                "DNS forwarding failed",
                error
            )

        } finally {

            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun parseDnsQuestionName(
        dnsPacket: ByteArray
    ): String? {

        if (
            dnsPacket.size < DNS_HEADER_LENGTH + 1
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
            position < dnsPacket.size &&
            labelCount < 128
        ) {

            val length =
                dnsPacket[position].toInt() and 0xFF

            position++

            if (length == 0) {
                break
            }

            /*
             * DNS compression is not valid for the initial
             * question-name sequence.
             */
            if (
                (length and 0xC0) == 0xC0
            ) {
                return null
            }

            if (
                length > 63 ||
                position + length > dnsPacket.size
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

            labels.add(
                label
            )

            position += length
            labelCount++
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
    ): ByteArray {

        /*
         * Return the original question with:
         *
         * QR = response
         * RA = recursion available
         * RCODE = NXDOMAIN
         *
         * No answer section is required for this blocking response.
         */

        if (query.size < DNS_HEADER_LENGTH) {
            return query
        }

        val response =
            query.copyOf()

        val originalFlags =
            readUnsignedShort(
                response,
                2
            )

        val newFlags =
            (originalFlags and 0x0100) or
                0x8000 or
                0x0080 or
                0x0003

        writeUnsignedShort(
            response,
            2,
            newFlags
        )

        /*
         * Answer count = 0
         */
        writeUnsignedShort(
            response,
            6,
            0
        )

        /*
         * Authority count = 0
         */
        writeUnsignedShort(
            response,
            8,
            0
        )

        /*
         * Additional count = 0
         */
        writeUnsignedShort(
            response,
            10,
            0
        )

        return response
    }

    private fun writeDnsResponse(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsResponse: ByteArray,
        output: FileOutputStream
    ) {

        if (dnsResponse.isEmpty()) {
            return
        }

        if (
            originalLength <
            ipHeaderLength
        ) {
            return
        }

        if (
            originalPacket.size < 20
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

        val responseSourceIp =
            destinationIp

        val responseDestinationIp =
            sourceIp

        val responseSourcePort =
            destinationPort

        val responseDestinationPort =
            sourcePort

        val udpLength =
            UDP_HEADER_LENGTH +
                dnsResponse.size

        val ipLength =
            IPV4_HEADER_LENGTH +
                udpLength

        if (ipLength > 65535) {
            return
        }

        val response =
            ByteArray(
                ipLength
            )

        /*
         * IPv4 header
         */
        response[0] =
            0x45.toByte()

        response[1] =
            0

        writeUnsignedShort(
            response,
            2,
            ipLength
        )

        /*
         * Identification
         */
        response[4] =
            originalPacket[4]

        response[5] =
            originalPacket[5]

        /*
         * Don't fragment.
         */
        response[6] =
            0x40

        response[7] =
            0

        /*
         * TTL
         */
        response[8] =
            64

        /*
         * UDP
         */
        response[9] =
            17

        /*
         * Header checksum = 0 before calculating.
         */
        response[10] =
            0

        response[11] =
            0

        System.arraycopy(
            responseSourceIp,
            0,
            response,
            12,
            4
        )

        System.arraycopy(
            responseDestinationIp,
            0,
            response,
            16,
            4
        )

        val ipChecksum =
            calculateChecksum(
                response,
                0,
                IPV4_HEADER_LENGTH
            )

        writeUnsignedShort(
            response,
            10,
            ipChecksum
        )

        /*
         * UDP header.
         */
        writeUnsignedShort(
            response,
            20,
            responseSourcePort
        )

        writeUnsignedShort(
            response,
            22,
            responseDestinationPort
        )

        writeUnsignedShort(
            response,
            24,
            udpLength
        )

        /*
         * IPv4 permits UDP checksum zero.
         */
        response[26] =
            0

        response[27] =
            0

        System.arraycopy(
            dnsResponse,
            0,
            response,
            IPV4_HEADER_LENGTH +
                UDP_HEADER_LENGTH,
            dnsResponse.size
        )

        try {

            output.write(
                response
            )

            output.flush()

        } catch (error: Exception) {

            android.util.Log.w(
                TAG,
                "Could not inject DNS response",
                error
            )
        }
    }

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
                    ).toLong() shl 8
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
            ((value ushr 8) and 0xFF)
                .toByte()

        data[offset + 1] =
            (value and 0xFF)
                .toByte()
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

                    android.util.Log.e(
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
                        12L * 60L * 60L * 1000L
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

                    } catch (error: Exception) {

                        android.util.Log.e(
                            TAG,
                            "Scheduled filter update failed",
                            error
                        )
                    }
                }
            }
    }

    private fun stopVpn() {

        val wasRunning =
            running.getAndSet(false)

        isRunning = false

        packetJob?.cancel()
        packetJob = null

        filterRefreshJob?.cancel()
        filterRefreshJob = null

        val descriptor =
            vpnInterface

        vpnInterface = null

        /*
         * Closing the VPN descriptor causes a blocked read()
         * in the packet loop to return instead of leaving the
         * coroutine stuck.
         */
        try {
            descriptor?.close()
        } catch (error: Exception) {
            android.util.Log.w(
                TAG,
                "Could not close VPN interface",
                error
            )
        }

        if (wasRunning) {

            try {

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

            } catch (error: Exception) {

                android.util.Log.w(
                    TAG,
                    "Could not stop foreground service",
                    error
                )
            }
        }

        stopSelf()
    }

    private fun createNotification(): Notification {

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
                "Ad and tracker protection is active"
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
            "DNS-level ad and tracker protection"

        manager.createNotificationChannel(
            channel
        )
    }

    override fun onDestroy() {

        stopVpn()

        serviceScope.cancel()

        super.onDestroy()
    }

    override fun onRevoke() {

        stopVpn()

        super.onRevoke()
    }

    override fun onBind(
        intent: Intent?
    ): IBinder? {

        return super.onBind(intent)
    }
}

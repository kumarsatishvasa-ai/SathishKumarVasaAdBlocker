package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
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

class DnsVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    private var vpnJob: Job? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO
        )

    private lateinit var preferences: AppPreferences

    private lateinit var repository: FilterRepository

    private lateinit var filter: DnsFilter

    override fun onCreate() {
        super.onCreate()

        preferences =
            AppPreferences(
                applicationContext
            )

        repository =
            FilterRepository(
                applicationContext,
                preferences
            )

        filter =
            DnsFilter(
                preferences
            )

        loadStoredRules()

        createNotificationChannel()
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int
    ): Int {

        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        if (!preferences.enabled.value) {
            stopVpn()
            return START_NOT_STICKY
        }

        try {
            createNotificationChannel()
            startVpnForeground()
        } catch (error: Exception) {

            Log.e(
                TAG,
                "Unable to start foreground service",
                error
            )

            preferences.setEnabled(false)
            stopVpn()

            return START_NOT_STICKY
        }

        startVpn()

        return START_STICKY
    }

    private fun startVpnForeground() {

        val notification =
            createNotification()

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

    private fun startVpn() {

        if (vpnInterface != null) {
            return
        }

        if (!preferences.enabled.value) {
            stopVpn()
            return
        }

        try {

            val builder =
                Builder()
                    .setSession(
                        getString(
                            R.string.app_name
                        )
                    )
                    .setMtu(
                        VPN_MTU
                    )
                    .addAddress(
                        VPN_ADDRESS,
                        32
                    )
                    .addRoute(
                        DNS_ADDRESS,
                        32
                    )
                    .addDnsServer(
                        DNS_ADDRESS
                    )

            /*
             * We only route DNS traffic through
             * the VPN.
             *
             * This prevents the VPN from becoming
             * the default route for all traffic.
             */
            vpnInterface =
                builder.establish()

            if (vpnInterface == null) {

                Log.e(
                    TAG,
                    "VPN interface could not be established"
                )

                stopVpn()
                return
            }

            vpnJob =
                serviceScope.launch {
                    runVpnLoop()
                }

            Log.d(
                TAG,
                "DNS VPN started"
            )

        } catch (error: Exception) {

            Log.e(
                TAG,
                "Unable to establish VPN",
                error
            )

            stopVpn()
        }
    }

    private suspend fun runVpnLoop() {

        val descriptor =
            vpnInterface
                ?: return

        val input =
            try {
                FileInputStream(
                    descriptor.fileDescriptor
                )
            } catch (error: Exception) {

                Log.e(
                    TAG,
                    "Unable to open VPN input",
                    error
                )

                return
            }

        val output =
            try {
                FileOutputStream(
                    descriptor.fileDescriptor
                )
            } catch (error: Exception) {

                Log.e(
                    TAG,
                    "Unable to open VPN output",
                    error
                )

                try {
                    input.close()
                } catch (_: Exception) {
                }

                return
            }

        val packetBuffer =
            ByteArray(
                MAX_VPN_PACKET_SIZE
            )

        try {

            while (
                serviceScope.isActive &&
                preferences.enabled.value &&
                vpnInterface != null
            ) {

                val length =
                    try {
                        input.read(
                            packetBuffer
                        )
                    } catch (error: Exception) {

                        if (
                            serviceScope.isActive &&
                            preferences.enabled.value
                        ) {

                            Log.e(
                                TAG,
                                "VPN read failed",
                                error
                            )
                        }

                        break
                    }

                if (length <= 0) {

                    delay(10)

                    continue
                }

                processPacket(
                    packetBuffer,
                    length,
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

    private fun processPacket(
        packet: ByteArray,
        length: Int,
        output: FileOutputStream
    ) {

        if (
            length <
            IPV4_HEADER_MIN_LENGTH
        ) {
            return
        }

        /*
         * IPv4 version.
         */
        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        /*
         * IPv4 header length.
         */
        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ipHeaderLength <
            IPV4_HEADER_MIN_LENGTH ||
            ipHeaderLength > length
        ) {
            return
        }

        /*
         * Ignore fragmented IPv4 packets.
         *
         * DNS queries handled here should not
         * require IP fragmentation.
         */
        val flagsAndFragment =
            readUnsignedShort(
                packet,
                6
            )

        if (
            (flagsAndFragment and
                IP_FRAGMENT_OFFSET_MASK) != 0
        ) {
            return
        }

        /*
         * UDP only.
         */
        val protocol =
            packet[9].toInt() and 0xFF

        if (protocol != UDP_PROTOCOL) {
            return
        }

        if (
            length <
            ipHeaderLength +
            UDP_HEADER_LENGTH
        ) {
            return
        }

        val udpOffset =
            ipHeaderLength

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
            udpLength > length
        ) {
            return
        }

        /*
         * We only process DNS requests
         * addressed to port 53.
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
            dnsLength >
            MAX_DNS_PACKET_SIZE
        ) {
            return
        }

        val dnsQuery =
            packet.copyOfRange(
                dnsOffset,
                dnsOffset + dnsLength
            )

        val query =
            DnsPacket.parseQuery(
                dnsQuery
            )
                ?: return

        val hostname =
            filter.normalizeHostname(
                query.hostname
            )

        if (hostname.isEmpty()) {
            return
        }

        /*
         * Blocked hostname.
         */
        if (
            filter.isBlocked(
                hostname
            )
        ) {

            preferences.incrementBlockedCount()

            val blockedResponse =
                DnsPacket.buildBlockedResponse(
                    query
                )

            writeDnsResponse(
                originalPacket = packet,
                originalLength = length,
                ipHeaderLength = ipHeaderLength,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                dnsResponse = blockedResponse,
                output = output
            )

            return
        }

        /*
         * Allowed hostname.
         *
         * Forward the DNS request to the
         * upstream resolver.
         */
        forwardDnsQuery(
            originalPacket = packet,
            originalLength = length,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsQuery = dnsQuery,
            output = output
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

        if (
            dnsQuery.isEmpty() ||
            dnsQuery.size >
            MAX_DNS_PACKET_SIZE
        ) {
            return
        }

        val socket =
            try {
                DatagramSocket()
            } catch (error: Exception) {

                Log.w(
                    TAG,
                    "Could not create DNS socket",
                    error
                )

                return
            }

        try {

            /*
             * Important:
             *
             * Protect the upstream socket from
             * the VPN itself. Otherwise the DNS
             * request could loop back through
             * this VPN.
             */
            if (!protect(socket)) {

                Log.w(
                    TAG,
                    "Could not protect DNS socket"
                )

                return
            }

            socket.soTimeout =
                UPSTREAM_TIMEOUT_MS

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

            val dnsResponse =
                responsePacket.data.copyOf(
                    responsePacket.length
                )

            writeDnsResponse(
                originalPacket = originalPacket,
                originalLength = originalLength,
                ipHeaderLength = ipHeaderLength,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                dnsResponse = dnsResponse,
                output = output
            )

        } catch (error: Exception) {

            /*
             * DNS failures should not crash
             * the VPN service.
             */
            Log.w(
                TAG,
                "Upstream DNS request failed",
                error
            )

        } finally {

            try {
                socket.close()
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
        dnsResponse: ByteArray,
        output: FileOutputStream
    ) {

        if (dnsResponse.isEmpty()) {
            return
        }

        if (
            dnsResponse.size >
            MAX_DNS_PACKET_SIZE
        ) {
            return
        }

        if (
            originalLength <
            ipHeaderLength +
            UDP_HEADER_LENGTH
        ) {
            return
        }

        /*
         * Original packet:
         *
         * source      = Android/VPN client
         * destination = 10.8.0.1
         *
         * Response packet:
         *
         * source      = 10.8.0.1
         * destination = Android/VPN client
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

        val responseSourceIp =
            originalDestinationIp

        val responseDestinationIp =
            originalSourceIp

        val responseSourcePort =
            destinationPort

        val responseDestinationPort =
            sourcePort

        val udpLength =
            UDP_HEADER_LENGTH +
                dnsResponse.size

        val ipLength =
            IPV4_HEADER_MIN_LENGTH +
                udpLength

        if (
            ipLength > MAX_IPV4_PACKET_SIZE
        ) {
            return
        }

        val response =
            ByteArray(
                ipLength
            )

        /*
         * IPv4 header.
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
         * Identification.
         */
        response[4] =
            0

        response[5] =
            0

        /*
         * Flags / fragment offset.
         */
        response[6] =
            0

        response[7] =
            0

        /*
         * TTL.
         */
        response[8] =
            64

        /*
         * UDP protocol.
         */
        response[9] =
            UDP_PROTOCOL.toByte()

        /*
         * Checksum initially zero.
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

        /*
         * IPv4 header checksum.
         */
        val ipChecksum =
            calculateChecksum(
                response,
                0,
                IPV4_HEADER_MIN_LENGTH
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
         * Zero UDP checksum is valid for
         * IPv4 UDP.
         */
        response[26] =
            0

        response[27] =
            0

        /*
         * DNS payload.
         */
        System.arraycopy(
            dnsResponse,
            0,
            response,
            IPV4_HEADER_MIN_LENGTH +
                UDP_HEADER_LENGTH,
            dnsResponse.size
        )

        try {

            output.write(
                response
            )

            output.flush()

        } catch (error: Exception) {

            Log.w(
                TAG,
                "Could not write DNS response",
                error
            )
        }
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
                ((data[index].toInt() and 0xFF) shl 8) or
                    (data[index + 1].toInt() and 0xFF)

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
            sum.inv() and
                0xFFFFL
            ).toInt()
    }

    private fun loadStoredRules() {

        try {

            val rules =
                repository.loadRules()

            filter.loadRules(
                rules
            )

            Log.d(
                TAG,
                "Loaded ${rules.size} filter rules"
            )

        } catch (error: Exception) {

            Log.e(
                TAG,
                "Could not load stored filter rules",
                error
            )
        }
    }

    private fun stopVpn() {

        vpnJob?.cancel()
        vpnJob = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }

        vpnInterface = null

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

        } catch (_: Exception) {
        }

        stopSelf()
    }

    private fun createNotification(): Notification {

        return NotificationCompat
            .Builder(
                this,
                NOTIFICATION_CHANNEL
            )
            .setContentTitle(
                getString(
                    R.string.vpn_notification_title
                )
            )
            .setContentText(
                getString(
                    R.string.vpn_notification_text
                )
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
                NOTIFICATION_CHANNEL,
                getString(
                    R.string.app_name
                ),
                NotificationManager.IMPORTANCE_LOW
            )

        channel.description =
            getString(
                R.string.vpn_notification_text
            )

        manager.createNotificationChannel(
            channel
        )
    }

    override fun onRevoke() {

        preferences.setEnabled(
            false
        )

        stopVpn()

        super.onRevoke()
    }

    override fun onDestroy() {

        vpnJob?.cancel()
        vpnJob = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }

        vpnInterface = null

        serviceScope.cancel()

        super.onDestroy()
    }

    companion object {

        const val ACTION_STOP =
            "com.sathishkumarvasa.adblocker.STOP"

        private const val TAG =
            "DnsVpnService"

        private const val NOTIFICATION_CHANNEL =
            "adblocker_vpn"

        private const val NOTIFICATION_ID =
            1001

        /*
         * Private address assigned to the VPN
         * interface.
         */
        private const val VPN_ADDRESS =
            "10.8.0.2"

        /*
         * DNS address exposed by the VPN.
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

        private const val UDP_PROTOCOL =
            17

        private const val IPV4_HEADER_MIN_LENGTH =
            20

        private const val UDP_HEADER_LENGTH =
            8

        private const val DNS_HEADER_LENGTH =
            12

        private const val VPN_MTU =
            1500

        private const val MAX_VPN_PACKET_SIZE =
            32767

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val MAX_IPV4_PACKET_SIZE =
            65535

        private const val IP_FRAGMENT_OFFSET_MASK =
            0x1FFF

        private const val UPSTREAM_TIMEOUT_MS =
            3000
    }
}

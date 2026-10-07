package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
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

        createNotificationChannel()

        try {
            startForeground(
                NOTIFICATION_ID,
                createNotification()
            )
        } catch (error: Exception) {

            android.util.Log.e(
                TAG,
                "Unable to start foreground service",
                error
            )

            stopVpn()
            return START_NOT_STICKY
        }

        if (!preferences.enabled.value) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()

        return START_STICKY
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

            vpnInterface =
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
                    .setBlocking(false)
                    .establish()

            if (vpnInterface == null) {

                android.util.Log.e(
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

        } catch (error: Exception) {

            android.util.Log.e(
                TAG,
                "Unable to start VPN",
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
            FileInputStream(
                descriptor.fileDescriptor
            )

        val output =
            FileOutputStream(
                descriptor.fileDescriptor
            )

        val packetBuffer =
            ByteArray(
                MAX_IP_PACKET_SIZE
            )

        try {

            while (
                serviceScope.isActive &&
                vpnInterface != null
            ) {

                val length =
                    try {

                        input.read(
                            packetBuffer
                        )

                    } catch (error: Exception) {

                        if (
                            serviceScope.isActive
                        ) {

                            android.util.Log.e(
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

        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ipHeaderLength <
            IPV4_HEADER_MIN_LENGTH
        ) {
            return
        }

        if (
            ipHeaderLength > length
        ) {
            return
        }

        val totalIpLength =
            readUnsignedShort(
                packet,
                2
            )

        if (
            totalIpLength <
            ipHeaderLength
        ) {
            return
        }

        val effectiveLength =
            minOf(
                length,
                totalIpLength
            )

        if (
            effectiveLength <
            ipHeaderLength +
            UDP_HEADER_LENGTH
        ) {
            return
        }

        /*
         * Only IPv4 UDP is handled.
         */
        val protocol =
            packet[9].toInt() and 0xFF

        if (
            protocol != UDP_PROTOCOL
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
            udpOffset + udpLength >
            effectiveLength
        ) {
            return
        }

        /*
         * DNS requests sent to our VPN DNS address.
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
            dnsOffset + dnsLength >
            effectiveLength
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

        if (
            hostname.isEmpty()
        ) {
            return
        }

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
                originalLength = effectiveLength,
                ipHeaderLength = ipHeaderLength,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                dnsResponse = blockedResponse,
                output = output
            )

            return
        }

        forwardDnsQuery(
            originalPacket = packet,
            originalLength = effectiveLength,
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

        val socket =
            DatagramSocket()

        try {

            /*
             * The upstream socket must bypass the VPN.
             * Otherwise DNS requests can loop back into
             * this service.
             */
            if (
                !protect(socket)
            ) {

                android.util.Log.w(
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

            android.util.Log.w(
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

        if (
            dnsResponse.isEmpty()
        ) {
            return
        }

        if (
            originalLength <
            ipHeaderLength
        ) {
            return
        }

        if (
            originalPacket.size <
            IPV4_HEADER_MIN_LENGTH
        ) {
            return
        }

        /*
         * Original packet:
         *
         * source      = Android application
         * destination = VPN DNS address
         *
         * Response packet:
         *
         * source      = VPN DNS address
         * destination = Android application
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
            ipLength > 65535
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
         * Fragment flags/offset.
         */
        response[6] =
            0

        response[7] =
            0

        /*
         * TTL.
         */
        response[8] =
            64.toByte()

        /*
         * UDP.
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
         * UDP checksum zero is valid for IPv4.
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

            android.util.Log.w(
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
            (
                (value ushr 8) and 0xFF
                ).toByte()

        data[offset + 1] =
            (
                value and 0xFF
                ).toByte()
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

            sum += word

            while (
                sum ushr 16 != 0L
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
                    ).toLong() shl 8
        }

        while (
            sum ushr 16 != 0L
        ) {

            sum =
                (sum and 0xFFFFL) +
                    (sum ushr 16)
        }

        return (
            sum.inv() and 0xFFFFL
            ).toInt()
    }

    private fun loadStoredRules() {

        try {

            val rules =
                repository.loadRules()

            filter.loadRules(
                rules
            )

            android.util.Log.d(
                TAG,
                "Loaded ${rules.size} filter rules"
            )

        } catch (error: Exception) {

            android.util.Log.e(
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

    override fun onRevoke() {

        stopVpn()

        super.onRevoke()
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

        private const val VPN_ADDRESS =
            "10.8.0.2"

        private const val DNS_ADDRESS =
            "10.8.0.1"

        private const val UPSTREAM_DNS =
            "8.8.8.8"

        private const val DNS_PORT =
            53

        private const val UDP_PROTOCOL =
            17

        private const val VPN_MTU =
            1500

        private const val IPV4_HEADER_MIN_LENGTH =
            20

        private const val UDP_HEADER_LENGTH =
            8

        private const val DNS_HEADER_LENGTH =
            12

        private const val MAX_DNS_PACKET_SIZE =
            4096

        private const val MAX_IP_PACKET_SIZE =
            32767

        private const val UPSTREAM_TIMEOUT_MS =
            3000
    }
}

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
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DnsVpnService : VpnService() {

    private var vpnInterface:
        ParcelFileDescriptor? = null

    private var vpnJob:
        Job? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() +
                Dispatchers.IO
        )

    private lateinit var preferences:
        AppPreferences

    private lateinit var repository:
        FilterRepository

    private lateinit var filter:
        DnsFilter

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

        if (
            intent?.action ==
            ACTION_STOP
        ) {

            stopVpn()

            return START_NOT_STICKY
        }

        startForeground(
            NOTIFICATION_ID,
            createNotification()
        )

        startVpn()

        return START_STICKY
    }

    private fun startVpn() {

        if (
            vpnInterface != null
        ) {
            return
        }

        if (
            !preferences.enabled.value
        ) {
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
                    .setMtu(1500)

                    /*
                     * IPv4 virtual address.
                     */
                    .addAddress(
                        "10.8.0.2",
                        32
                    )

                    /*
                     * Route DNS traffic only.
                     *
                     * This avoids pretending to be a
                     * complete packet-routing VPN.
                     */
                    .addRoute(
                        "10.8.0.1",
                        32
                    )

                    /*
                     * DNS server address exposed to apps.
                     */
                    .addDnsServer(
                        "10.8.0.1"
                    )

                    .setBlocking(
                        false
                    )

                    .establish()

            if (
                vpnInterface == null
            ) {
                return
            }

            vpnJob =
                serviceScope.launch {
                    runDnsLoop()
                }

        } catch (
            _: Exception
        ) {

            stopVpn()
        }
    }

    private suspend fun runDnsLoop() {

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
                32767
            )

        /*
         * The simplified first implementation uses
         * a userspace DNS tunnel.
         *
         * If the interface doesn't produce a
         * recognizable IP packet, we simply ignore it.
         */
        while (
            serviceScope.isActive
        ) {

            try {

                val bytesRead =
                    input.read(
                        packetBuffer
                    )

                if (
                    bytesRead <= 0
                ) {
                    delay(10)
                    continue
                }

                processIpPacket(
                    packetBuffer,
                    bytesRead,
                    output
                )

            } catch (
                _: Exception
            ) {

                if (
                    serviceScope.isActive
                ) {
                    delay(100)
                }
            }
        }
    }

    private fun processIpPacket(
        packet: ByteArray,
        length: Int,
        output: FileOutputStream
    ) {

        if (length < 20) {
            return
        }

        val version =
            (packet[0].toInt() shr 4) and 0x0F

        /*
         * IPv4 only for the first implementation.
         */
        if (version != 4) {
            return
        }

        val ihl =
            (packet[0].toInt() and 0x0F) * 4

        if (
            ihl < 20 ||
            length < ihl
        ) {
            return
        }

        val protocol =
            packet[9].toInt() and 0xFF

        /*
         * UDP.
         */
        if (protocol != 17) {
            return
        }

        if (
            length < ihl + 8
        ) {
            return
        }

        val udpOffset =
            ihl

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
            udpLength < 8 ||
            udpOffset + udpLength > length
        ) {
            return
        }

        /*
         * DNS normally uses destination port 53.
         */
        if (
            destinationPort != 53
        ) {
            return
        }

        val dnsOffset =
            udpOffset + 8

        val dnsLength =
            udpLength - 8

        if (
            dnsLength <= 0
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
            filter.isBlocked(
                hostname
            )
        ) {

            preferences.incrementBlockedCount()

            val response =
                DnsPacket.buildBlockedResponse(
                    query
                )

            writeUdpResponse(
                originalPacket =
                    packet,

                originalLength =
                    length,

                ipHeaderLength =
                    ihl,

                sourcePort =
                    sourcePort,

                destinationPort =
                    destinationPort,

                dnsResponse =
                    response,

                output =
                    output
            )

            return
        }

        /*
         * Allowed DNS request.
         *
         * The first version forwards it to an upstream
         * resolver through a normal UDP socket.
         */
        forwardDnsQuery(
            originalPacket =
                packet,

            originalLength =
                length,

            ipHeaderLength =
                ihl,

            sourcePort =
                sourcePort,

            destinationPort =
                destinationPort,

            dnsQuery =
                dnsQuery,

            output =
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

        /*
         * Google Public DNS.
         *
         * We explicitly protect the socket so the DNS
         * request does not recursively enter our own VPN.
         */
        val socket =
            DatagramSocket()

        try {

            if (
                !protect(socket)
            ) {
                return
            }

            val server =
                InetSocketAddress(
                    "8.8.8.8",
                    53
                )

            val request =
                DatagramPacket(
                    dnsQuery,
                    dnsQuery.size,
                    server
                )

            socket.soTimeout =
                3000

            socket.send(
                request
            )

            val buffer =
                ByteArray(4096)

            val response =
                DatagramPacket(
                    buffer,
                    buffer.size
                )

            socket.receive(
                response
            )

            val dnsResponse =
                response.data.copyOf(
                    response.length
                )

            writeUdpResponse(
                originalPacket =
                    originalPacket,

                originalLength =
                    originalLength,

                ipHeaderLength =
                    ipHeaderLength,

                sourcePort =
                    sourcePort,

                destinationPort =
                    destinationPort,

                dnsResponse =
                    dnsResponse,

                output =
                    output
            )

        } catch (
            _: Exception
        ) {

            /*
             * DNS failure is intentionally silent here.
             */

        } finally {

            socket.close()
        }
    }

    private fun writeUdpResponse(
        originalPacket: ByteArray,
        originalLength: Int,
        ipHeaderLength: Int,
        sourcePort: Int,
        destinationPort: Int,
        dnsResponse: ByteArray,
        output: FileOutputStream
    ) {

        /*
         * Extract original IPv4 source/destination.
         *
         * Original packet:
         *
         * source = app
         * destination = virtual DNS
         *
         * Response:
         *
         * source = virtual DNS
         * destination = app
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

        val responseSourceIp =
            destinationIp

        val responseDestinationIp =
            sourceIp

        val responseSourcePort =
            destinationPort

        val responseDestinationPort =
            sourcePort

        val udpLength =
            8 +
                dnsResponse.size

        val ipLength =
            20 +
                udpLength

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

        writeShort(
            response,
            2,
            ipLength
        )

        /*
         * Identification.
         */
        response[4] = 0
        response[5] = 0

        /*
         * Flags / fragment offset.
         */
        response[6] = 0
        response[7] = 0

        /*
         * TTL.
         */
        response[8] =
            64

        /*
         * UDP.
         */
        response[9] =
            17

        /*
         * Header checksum initially zero.
         */
        response[10] = 0
        response[11] = 0

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
            checksum(
                response,
                0,
                20
            )

        writeShort(
            response,
            10,
            ipChecksum
        )

        /*
         * UDP header.
         */
        writeShort(
            response,
            20,
            responseSourcePort
        )

        writeShort(
            response,
            22,
            responseDestinationPort
        )

        writeShort(
            response,
            24,
            udpLength
        )

        /*
         * UDP checksum.
         *
         * IPv4 allows zero checksum for UDP.
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

        output.write(
            response
        )

        output.flush()
    }

    private fun readUnsignedShort(
        data: ByteArray,
        offset: Int
    ): Int {

        return (
            ((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)
            )
    }

    private fun writeShort(
        data: ByteArray,
        offset: Int,
        value: Int
    ) {

        data[offset] =
            ((value shr 8) and 0xFF)
                .toByte()

        data[offset + 1] =
            (value and 0xFF)
                .toByte()
    }

    private fun checksum(
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

            sum += word

            while (
                sum shr 16 != 0L
            ) {
                sum =
                    (sum and 0xFFFF) +
                        (sum shr 16)
            }

            index += 2
        }

        if (
            index < end
        ) {

            sum +=
                (data[index].toInt() and 0xFF) shl 8
        }

        while (
            sum shr 16 != 0L
        ) {
            sum =
                (sum and 0xFFFF) +
                    (sum shr 16)
        }

        return (
            sum.inv() and
                0xFFFF
            )
    }

    private fun loadStoredRules() {

        try {

            val rules =
                repository.loadRules()

            filter.loadRules(
                rules
            )

        } catch (
            _: Exception
        ) {
            /*
             * Start with an empty filter if local
             * rules cannot be loaded.
             */
        }
    }

    private fun stopVpn() {

        vpnJob?.cancel()

        vpnJob = null

        try {
            vpnInterface?.close()
        } catch (
            _: Exception
        ) {
        }

        vpnInterface = null

        stopForeground(
            STOP_FOREGROUND_REMOVE
        )

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
                NotificationManager
                    .IMPORTANCE_LOW
            )

        manager.createNotificationChannel(
            channel
        )
    }

    override fun onDestroy() {

        vpnJob?.cancel()

        vpnInterface?.close()

        serviceScope.cancel()

        super.onDestroy()
    }

    companion object {

        const val ACTION_STOP =
            "com.sathishkumarvasa.adblocker.STOP"

        private const val NOTIFICATION_CHANNEL =
            "adblocker_vpn"

        private const val NOTIFICATION_ID =
            1001
    }
}


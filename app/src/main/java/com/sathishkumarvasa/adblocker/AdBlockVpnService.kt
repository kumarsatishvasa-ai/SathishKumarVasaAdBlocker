package com.sathishkumarvasa.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
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

        private const val MTU =
            1500

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    private var inputStream: FileInputStream? = null

    private var outputStream: FileOutputStream? = null

    private var packetJob: Job? = null

    private var filterRefreshJob: Job? = null

    private val serviceScope =
        CoroutineScope(
            Dispatchers.IO
        )

    private val running =
        AtomicBoolean(false)


    // =====================================================
    // SERVICE CREATION
    // =====================================================

    override fun onCreate() {
        super.onCreate()

        createNotificationChannel()
    }


    // =====================================================
    // START / STOP
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
            !AdBlockStorage.isEnabled(this)
        ) {
            return
        }

        val builder =
            Builder()

        builder
            .setSession(
                "SATHISH KUMAR VASA Ad Blocker"
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
                DNS_ADDRESS
            )


        /*
         * Do not capture the VPN service's own traffic.
         *
         * The VPN is intended to inspect application traffic,
         * while our service needs to remain functional.
         */
        try {
            builder.addDisallowedApplication(
                packageName
            )
        } catch (error: Exception) {
            error.printStackTrace()
        }


        try {

            vpnInterface =
                builder.establish()

            if (vpnInterface == null) {
                return
            }

            running.set(true)
            isRunning = true


            startForeground(
                NOTIFICATION_ID,
                createNotification()
            )


            inputStream =
                FileInputStream(
                    vpnInterface!!.fileDescriptor
                )


            outputStream =
                FileOutputStream(
                    vpnInterface!!.fileDescriptor
                )


            startPacketLoop()
            startFilterRefreshLoop()

        } catch (error: Exception) {

            error.printStackTrace()

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
                    ByteArray(MTU)


                while (
                    isActive &&
                    running.get()
                ) {

                    try {

                        val count =
                            inputStream?.read(
                                buffer
                            )
                                ?: break


                        if (count <= 0) {
                            continue
                        }


                        val packet =
                            buffer.copyOf(
                                count
                            )


                        processPacket(
                            packet
                        )

                    } catch (
                        error: Exception
                    ) {

                        if (
                            running.get()
                        ) {
                            error.printStackTrace()
                        }

                        break
                    }
                }
            }
    }


    // =====================================================
    // PACKET PROCESSING
    // =====================================================

    private fun processPacket(
        packet: ByteArray
    ) {

        /*
         * IPv4 packets have version 4 in the high nibble.
         */
        if (packet.isEmpty()) {
            return
        }


        val version =
            (packet[0].toInt() shr 4) and 0x0F


        if (version != 4) {

            /*
             * IPv6 support is intentionally not enabled in this
             * first implementation. We configure only IPv4.
             */
            return
        }


        val protocol =
            packet[9].toInt() and 0xFF


        when (protocol) {

            17 -> {
                processUdpPacket(
                    packet
                )
            }

            else -> {
                /*
                 * TCP/other packets are not handled by this
                 * lightweight DNS blocker.
                 *
                 * A complete transparent VPN proxy would need
                 * TCP/UDP forwarding here.
                 */
            }
        }
    }


    // =====================================================
    // UDP
    // =====================================================

    private fun processUdpPacket(
        packet: ByteArray
    ) {

        val ipHeaderLength =
            (packet[0].toInt() and 0x0F) * 4


        if (
            packet.size <
            ipHeaderLength + 8
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


        /*
         * DNS normally uses UDP port 53.
         */
        if (
            destinationPort == 53
        ) {

            processDnsQuery(
                packet,
                ipHeaderLength,
                sourcePort
            )

            return
        }


        /*
         * For non-DNS UDP traffic we currently do not
         * forward the packet.
         */
    }


    // =====================================================
    // DNS QUERY
    // =====================================================

    private fun processDnsQuery(
        packet: ByteArray,
        ipHeaderLength: Int,
        sourcePort: Int
    ) {

        val dnsOffset =
            ipHeaderLength + 8


        if (
            packet.size <= dnsOffset + 12
        ) {
            return
        }


        val hostname =
            parseDnsQuestionName(
                packet,
                dnsOffset
            )
                ?: return


        val blocked =
            FilterManager.isBlockedHost(
                this,
                hostname
            )


        if (blocked) {

            AdBlockStorage.incrementBlockedCount(
                this
            )


            sendBlockedDnsResponse(
                packet,
                ipHeaderLength,
                dnsOffset
            )

        } else {

            /*
             * In this basic implementation, DNS queries are
             * not forwarded through the VPN interface.
             *
             * The next-stage implementation should provide
             * an upstream DNS resolver and packet forwarding
             * for complete browsing support.
             */
        }
    }


    // =====================================================
    // DNS NAME PARSER
    // =====================================================

    private fun parseDnsQuestionName(
        packet: ByteArray,
        dnsOffset: Int
    ): String? {

        var position =
            dnsOffset + 12


        val labels =
            mutableListOf<String>()


        while (
            position < packet.size
        ) {

            val length =
                packet[position].toInt() and 0xFF


            position++


            if (length == 0) {
                break
            }


            /*
             * Compression pointers are not expected in the
             * question name, but reject them safely.
             */
            if (
                (length and 0xC0) == 0xC0
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
                packet
                    .copyOfRange(
                        position,
                        position + length
                    )
                    .toString(
                        Charsets.US_ASCII
                    )


            labels.add(
                label
            )


            position += length
        }


        if (labels.isEmpty()) {
            return null
        }


        return labels.joinToString(".")
            .lowercase()
    }


    // =====================================================
    // BLOCKED DNS RESPONSE
    // =====================================================

    private fun sendBlockedDnsResponse(
        originalPacket: ByteArray,
        ipHeaderLength: Int,
        dnsOffset: Int
    ) {

        /*
         * A complete DNS packet response requires rebuilding
         * the IPv4 + UDP + DNS headers and checksums.
         *
         * This function intentionally does not inject a
         * malformed packet into the VPN interface.
         *
         * The query is therefore dropped.
         */
    }


    // =====================================================
    // FILTER REFRESH
    // =====================================================

    private fun startFilterRefreshLoop() {

        filterRefreshJob?.cancel()


        filterRefreshJob =
            serviceScope.launch {

                /*
                 * Download filters once when VPN starts.
                 */
                FilterManager.updateFilters(
                    this@AdBlockVpnService
                )


                while (
                    isActive &&
                    running.get()
                ) {

                    delay(
                        12 * 60 * 60 * 1000L
                    )


                    if (
                        !running.get()
                    ) {
                        break
                    }


                    FilterManager.updateFilters(
                        this@AdBlockVpnService
                    )
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


        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }

        vpnInterface = null


        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(
                STOP_FOREGROUND_REMOVE
            )
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }


        stopSelf()
    }


    // =====================================================
    // FOREGROUND NOTIFICATION
    // =====================================================

    private fun createNotification(): Notification {

        return NotificationCompat.Builder(
            this,
            CHANNEL_ID
        )
            .setContentTitle(
                "SATHISH KUMAR VASA Ad Blocker"
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
            "VPN protection for ad and tracker blocking"


        manager.createNotificationChannel(
            channel
        )
    }


    // =====================================================
    // UTILITY
    // =====================================================

    private fun readUnsignedShort(
        data: ByteArray,
        offset: Int
    ): Int {

        if (
            offset + 1 >= data.size
        ) {
            return 0
        }


        return (
            ((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)
            )
    }


    // =====================================================
    // SERVICE DESTROY
    // =====================================================

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

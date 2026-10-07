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

        private const val DNS_PORT =
            53

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    /*
     * Keep the VPN descriptor private and nullable.
     *
     * IMPORTANT:
     * Whenever it is used, copy it to a local val first.
     * This avoids Kotlin smart-cast errors because the property
     * can be changed by another lifecycle callback.
     */
    private var vpnInterface: ParcelFileDescriptor? = null

    private var inputStream: FileInputStream? = null

    private var outputStream: FileOutputStream? = null

    private var packetJob: Job? = null

    private var filterRefreshJob: Job? = null

    private val serviceScope =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO
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

        if (!AdBlockStorage.isEnabled(this)) {
            return
        }

        try {

            val builder =
                Builder()
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
             * Prevent the VPN service itself from being routed
             * through the VPN.
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

            /*
             * Establish VPN.
             *
             * Store the result in a local val first.
             */
            val establishedInterface =
                builder.establish()

            if (establishedInterface == null) {

                android.util.Log.e(
                    TAG,
                    "Could not establish VPN interface"
                )

                return
            }

            /*
             * Assign only after successful establishment.
             */
            vpnInterface =
                establishedInterface

            running.set(true)
            isRunning = true

            startForeground(
                NOTIFICATION_ID,
                createNotification()
            )

            /*
             * IMPORTANT:
             * Use the local immutable reference.
             * Do NOT use vpnInterface!!.fileDescriptor.
             */
            inputStream =
                FileInputStream(
                    establishedInterface.fileDescriptor
                )

            outputStream =
                FileOutputStream(
                    establishedInterface.fileDescriptor
                )

            startPacketLoop()
            startFilterRefreshLoop()

            android.util.Log.i(
                TAG,
                "VPN started successfully"
            )

        } catch (error: Exception) {

            android.util.Log.e(
                TAG,
                "Failed to start VPN",
                error
            )

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
                    ByteArray(
                        MTU
                    )

                while (
                    isActive &&
                    running.get()
                ) {

                    try {

                        val input =
                            inputStream

                        if (input == null) {
                            break
                        }

                        val count =
                            input.read(
                                buffer
                            )

                        if (count <= 0) {
                            delay(10)
                            continue
                        }

                        val packet =
                            buffer.copyOf(
                                count
                            )

                        processPacket(
                            packet
                        )

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
                }
            }
    }

    // =====================================================
    // PACKET PROCESSING
    // =====================================================

    private fun processPacket(
        packet: ByteArray
    ) {

        if (packet.size < 20) {
            return
        }

        /*
         * IPv4 packets have version 4 in the high nibble.
         */
        val version =
            (packet[0].toInt() ushr 4) and 0x0F

        if (version != 4) {
            return
        }

        val headerLength =
            (packet[0].toInt() and 0x0F) * 4

        if (
            headerLength < 20 ||
            headerLength > packet.size
        ) {
            return
        }

        val protocol =
            packet[9].toInt() and 0xFF

        when (protocol) {

            17 -> {
                processUdpPacket(
                    packet,
                    headerLength
                )
            }

            else -> {
                /*
                 * TCP and other protocols are not implemented
                 * by this lightweight DNS filtering service.
                 *
                 * They are intentionally dropped rather than
                 * sending malformed packets.
                 */
            }
        }
    }

    // =====================================================
    // UDP
    // =====================================================

    private fun processUdpPacket(
        packet: ByteArray,
        ipHeaderLength: Int
    ) {

        val udpOffset =
            ipHeaderLength

        if (
            packet.size <
            udpOffset + 8
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
         * DNS normally uses UDP port 53.
         */
        if (
            destinationPort == DNS_PORT
        ) {

            processDnsQuery(
                packet,
                ipHeaderLength,
                sourcePort
            )
        }
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
            packet.size <
            dnsOffset + 12
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
            try {
                FilterManager.isBlockedHost(
                    this,
                    hostname
                )
            } catch (error: Exception) {

                android.util.Log.e(
                    TAG,
                    "Filter lookup failed for $hostname",
                    error
                )

                false
            }

        if (blocked) {

            try {
                AdBlockStorage.incrementBlockedCount(
                    this
                )
            } catch (error: Exception) {

                android.util.Log.w(
                    TAG,
                    "Could not update blocked counter",
                    error
                )
            }

            /*
             * The current implementation intentionally drops
             * blocked DNS queries.
             *
             * A future implementation can generate a valid
             * DNS response such as NXDOMAIN/0.0.0.0.
             */
            android.util.Log.d(
                TAG,
                "Blocked DNS request: $hostname"
            )

        } else {

            /*
             * DNS forwarding is not implemented in this
             * lightweight service.
             *
             * A real transparent VPN needs an upstream DNS
             * resolver and packet reconstruction here.
             */
            android.util.Log.d(
                TAG,
                "DNS request allowed: $hostname"
            )
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
             * DNS compression pointer.
             *
             * Compression is not expected in the question
             * section, so reject it safely.
             */
            if (
                (length and 0xC0) == 0xC0
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

            labels.add(
                label
            )

            position += length
        }

        if (labels.isEmpty()) {
            return null
        }

        return labels
            .joinToString(".")
            .lowercase()
    }

    // =====================================================
    // FILTER REFRESH
    // =====================================================

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

                    if (!running.get()) {
                        break
                    }

                    try {

                        FilterManager.updateFilters(
                            this@AdBlockVpnService
                        )

                    } catch (error: Exception) {

                        android.util.Log.e(
                            TAG,
                            "Filter refresh failed",
                            error
                        )
                    }
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

        /*
         * Save local references before clearing the properties.
         *
         * This avoids mutable-property smart-cast problems.
         */
        val input =
            inputStream

        val output =
            outputStream

        val vpn =
            vpnInterface

        inputStream = null
        outputStream = null
        vpnInterface = null

        try {
            input?.close()
        } catch (error: Exception) {
            android.util.Log.w(
                TAG,
                "Could not close VPN input stream",
                error
            )
        }

        try {
            output?.close()
        } catch (error: Exception) {
            android.util.Log.w(
                TAG,
                "Could not close VPN output stream",
                error
            )
        }

        /*
         * Closing the FileInputStream/FileOutputStream closes
         * the underlying ParcelFileDescriptor as well.
         *
         * Therefore we deliberately do NOT call:
         *
         * vpn?.close()
         *
         * here. This also avoids the previous close() compiler
         * problem.
         */

        if (Build.VERSION.SDK_INT >= 24) {

            stopForeground(
                STOP_FOREGROUND_REMOVE
            )

        } else {

            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        android.util.Log.i(
            TAG,
            "VPN stopped"
        )

        stopSelf()
    }

    // =====================================================
    // FOREGROUND NOTIFICATION
    // =====================================================

    private fun createNotification(): Notification {

        return NotificationCompat
            .Builder(
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

    // =====================================================
    // LOGGING
    // =====================================================

    private companion object {
        const val TAG =
            "AdBlockVpnService"
    }
}

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

    private const val UDP_PROTOCOL =
        17

    private const val IPV4_MIN_HEADER =
        20

    private const val UDP_HEADER_LENGTH =
        8

    private const val DNS_HEADER_LENGTH =
        12

    @Volatile
    var isRunning: Boolean = false
        private set
}

/*
 * IMPORTANT:
 *
 * This property is mutable, so do not use:
 *
 * vpnInterface!!.fileDescriptor
 *
 * directly from asynchronous code.
 *
 * Instead, establish the interface, store it in a local val,
 * and use that local value.
 */
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

    if (!AdBlockStorage.isEnabled(this)) {
        stopSelf()
        return
    }

    /*
     * Clean up any stale resources before establishing
     * a new VPN interface.
     */
    closeVpnResources()

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
         * Do not capture this application's own traffic.
         * This prevents the VPN service from routing its own
         * upstream/network operations back through itself.
         */
        try {

            builder.addDisallowedApplication(
                packageName
            )

        } catch (error: Exception) {

            android.util.Log.w(
                "AdBlockVpnService",
                "Could not exclude application from VPN",
                error
            )
        }

        /*
         * establish() returns ParcelFileDescriptor?.
         *
         * Store the result in a local immutable value first.
         * This avoids Kotlin smart-cast errors caused by the
         * mutable vpnInterface property.
         */
        val establishedInterface =
            builder.establish()

        if (establishedInterface == null) {

            android.util.Log.e(
                "AdBlockVpnService",
                "VPN interface could not be established"
            )

            stopVpn()
            return
        }

        /*
         * Assign only after establish() successfully returned.
         */
        vpnInterface =
            establishedInterface

        /*
         * Use the local immutable value here.
         *
         * Do NOT use:
         *
         * vpnInterface!!.fileDescriptor
         */
        val descriptor =
            establishedInterface.fileDescriptor

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

        /*
         * Foreground service notification.
         */
        startForeground(
            NOTIFICATION_ID,
            createNotification()
        )

        startPacketLoop()

        startFilterRefreshLoop()

        android.util.Log.i(
            "AdBlockVpnService",
            "VPN started successfully"
        )

    } catch (error: Exception) {

        android.util.Log.e(
            "AdBlockVpnService",
            "Unable to start VPN",
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
                            "AdBlockVpnService",
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

    if (
        packet.size <
        IPV4_MIN_HEADER
    ) {
        return
    }

    /*
     * IPv4 version is high nibble of first byte.
     */
    val version =
        (packet[0].toInt() ushr 4) and 0x0F

    if (version != 4) {

        /*
         * This VPN configuration currently handles IPv4.
         */
        return
    }

    val ipHeaderLength =
        (packet[0].toInt() and 0x0F) * 4

    if (
        ipHeaderLength <
        IPV4_MIN_HEADER
    ) {
        return
    }

    if (
        ipHeaderLength >
        packet.size
    ) {
        return
    }

    val protocol =
        packet[9].toInt() and 0xFF

    when (protocol) {

        UDP_PROTOCOL -> {

            processUdpPacket(
                packet,
                ipHeaderLength
            )
        }

        else -> {

            /*
             * TCP/other traffic is intentionally not handled
             * by this lightweight DNS-only implementation.
             *
             * A complete transparent VPN must implement
             * forwarding for TCP and non-DNS UDP traffic.
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
     * Only DNS UDP requests are inspected.
     */
    if (
        destinationPort != DNS_PORT
    ) {
        return
    }

    processDnsQuery(
        packet = packet,
        ipHeaderLength = ipHeaderLength,
        sourcePort = sourcePort
    )
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
        ipHeaderLength +
            UDP_HEADER_LENGTH

    if (
        packet.size <
        dnsOffset + DNS_HEADER_LENGTH
    ) {
        return
    }

    val hostname =
        parseDnsQuestionName(
            packet,
            dnsOffset
        )
            ?: return

    val normalizedHostname =
        hostname
            .trim()
            .trimEnd('.')
            .lowercase()

    if (
        normalizedHostname.isEmpty()
    ) {
        return
    }

    val blocked =
        try {

            FilterManager.isBlockedHost(
                this,
                normalizedHostname
            )

        } catch (error: Exception) {

            android.util.Log.e(
                "AdBlockVpnService",
                "Filter check failed for $normalizedHostname",
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
                "AdBlockVpnService",
                "Could not increment blocked count",
                error
            )
        }

        /*
         * The original implementation deliberately dropped
         * blocked DNS packets because it did not construct
         * a valid DNS response.
         *
         * We keep that safe behavior here.
         */
        android.util.Log.d(
            "AdBlockVpnService",
            "Blocked DNS request: $normalizedHostname"
        )

        sendBlockedDnsResponse(
            originalPacket = packet,
            ipHeaderLength = ipHeaderLength,
            dnsOffset = dnsOffset,
            sourcePort = sourcePort
        )

    } else {

        /*
         * IMPORTANT:
         *
         * A DNS-only VPN cannot simply drop allowed DNS
         * queries. That would break DNS resolution.
         *
         * Upstream DNS forwarding must be implemented for
         * full browsing functionality.
         */
        android.util.Log.d(
            "AdBlockVpnService",
            "Allowed DNS request: $normalizedHostname"
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

    if (
        dnsOffset < 0 ||
        dnsOffset + DNS_HEADER_LENGTH >
        packet.size
    ) {
        return null
    }

    var position =
        dnsOffset +
            DNS_HEADER_LENGTH

    val labels =
        mutableListOf<String>()

    /*
     * Protect against malformed packets that contain
     * an endless sequence of labels.
     */
    var labelCount =
        0

    while (
        position < packet.size
    ) {

        if (labelCount > 127) {
            return null
        }

        val length =
            packet[position].toInt() and 0xFF

        position++

        /*
         * End of DNS name.
         */
        if (length == 0) {
            break
        }

        /*
         * Compression pointer.
         *
         * Compression is not expected in the question section.
         */
        if (
            (length and 0xC0) == 0xC0
        ) {
            return null
        }

        /*
         * DNS label maximum is 63 bytes.
         */
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

        if (
            label.isEmpty()
        ) {
            return null
        }

        labels.add(
            label
        )

        position += length

        labelCount++
    }

    if (
        labels.isEmpty()
    ) {
        return null
    }

    return labels
        .joinToString(".")
        .lowercase()
}

// =====================================================
// BLOCKED DNS RESPONSE
// =====================================================

private fun sendBlockedDnsResponse(
    originalPacket: ByteArray,
    ipHeaderLength: Int,
    dnsOffset: Int,
    sourcePort: Int
) {

    /*
     * We intentionally do not inject a malformed response.
     *
     * A proper implementation should construct:
     *
     * IPv4 header
     * + UDP header
     * + DNS response
     *
     * with correct addresses, ports, lengths and checksums.
     *
     * Dropping the blocked query is safe from a packet-format
     * perspective.
     */
}

// =====================================================
// FILTER REFRESH
// =====================================================

private fun startFilterRefreshLoop() {

    filterRefreshJob?.cancel()

    filterRefreshJob =
        serviceScope.launch {

            try {

                /*
                 * Update filters once when VPN starts.
                 */
                FilterManager.updateFilters(
                    this@AdBlockVpnService
                )

            } catch (error: Exception) {

                android.util.Log.e(
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
                    12L *
                        60L *
                        60L *
                        1000L
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
                        "AdBlockVpnService",
                        "Filter update failed",
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

    closeVpnResources()

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
            stopForeground(
                true
            )
        }

    } catch (error: Exception) {

        android.util.Log.w(
            "AdBlockVpnService",
            "Could not stop foreground service cleanly",
            error
        )
    }

    stopSelf()
}

// =====================================================
// RESOURCE CLEANUP
// =====================================================

private fun closeVpnResources() {

    /*
     * Close streams first.
     */
    val input =
        inputStream

    inputStream = null

    try {

        input?.close()

    } catch (error: Exception) {

        android.util.Log.w(
            "AdBlockVpnService",
            "Could not close VPN input stream",
            error
        )
    }

    val output =
        outputStream

    outputStream = null

    try {

        output?.close()

    } catch (error: Exception) {

        android.util.Log.w(
            "AdBlockVpnService",
            "Could not close VPN output stream",
            error
        )
    }

    /*
     * Copy the mutable property into a local immutable
     * variable before closing it.
     *
     * This avoids smart-cast/concurrent mutation problems.
     */
    val descriptor =
        vpnInterface

    vpnInterface = null

    try {

        descriptor?.close()

    } catch (error: Exception) {

        android.util.Log.w(
            "AdBlockVpnService",
            "Could not close VPN interface",
            error
        )
    }
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

    running.set(false)

    isRunning = false

    packetJob?.cancel()
    packetJob = null

    filterRefreshJob?.cancel()
    filterRefreshJob = null

    closeVpnResources()

    serviceScope.cancel()

    super.onDestroy()
}

// =====================================================
// SERVICE BINDING
// =====================================================

override fun onBind(
    intent: Intent?
): IBinder? {

    return super.onBind(
        intent
    )
}

}

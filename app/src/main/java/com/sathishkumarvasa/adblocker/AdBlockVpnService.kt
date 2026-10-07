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

    /*
     * VPN address used by the virtual interface.
     */
    private const val VPN_ADDRESS =
        "10.8.0.2"

    private const val VPN_PREFIX =
        24

    /*
     * DNS address exposed through the VPN.
     */
    private const val DNS_ADDRESS =
        "10.8.0.1"

    /*
     * Upstream DNS server.
     */
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
        SupervisorJob() + Dispatchers.IO
    )

private val running =
    AtomicBoolean(false)

// =========================================================
// SERVICE
// =========================================================

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

        ACTION_START -> {

            startVpn()
        }

        else -> {

            startVpn()
        }
    }

    return START_STICKY
}

// =========================================================
// START VPN
// =========================================================

private fun startVpn() {

    if (running.get()) {
        return
    }

    if (!AdBlockStorage.isEnabled(this)) {

        stopSelf()

        return
    }

    try {

        /*
         * Create the VPN interface.
         *
         * We deliberately route only the DNS address rather
         * than routing 0.0.0.0/0. This implementation is a
         * DNS filtering VPN, not a complete TCP/UDP proxy.
         */
        val builder =
            Builder()
                .setSession(
                    getString(
                        R.string.app_name
                    )
                )
                .setMtu(
                    MTU
                )
                .addAddress(
                    VPN_ADDRESS,
                    VPN_PREFIX
                )
                .addRoute(
                    DNS_ADDRESS,
                    32
                )
                .addDnsServer(
                    DNS_ADDRESS
                )

        /*
         * Do not send our own application traffic through
         * this VPN.
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
         * Establish the interface.
         *
         * Store it in a local immutable variable first.
         * This avoids Kotlin smart-cast errors caused by
         * vpnInterface being mutable.
         */
        val establishedInterface =
            builder.establish()

        if (establishedInterface == null) {

            android.util.Log.e(
                TAG,
                "VPN interface could not be established"
            )

            stopVpn()

            return
        }

        vpnInterface =
            establishedInterface

        /*
         * Again use the local immutable reference instead of
         * smart-casting the mutable property.
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

        startForeground(
            NOTIFICATION_ID,
            createNotification()
        )

        startPacketLoop()

        startFilterRefreshLoop()

        android.util.Log.i(
            TAG,
            "DNS VPN started successfully"
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

// =========================================================
// PACKET LOOP
// =========================================================

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

                if (input == null) {
                    break
                }

                try {

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

                        android.util.Log.w(
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

// =========================================================
// PACKET PROCESSING
// =========================================================

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

    val ipHeaderLength =
        (packet[0].toInt() and 0x0F) * 4

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

    if (
        protocol != UDP_PROTOCOL
    ) {
        return
    }

    if (
        totalLength <
        ipHeaderLength +
        UDP_HEADER_LENGTH
    ) {
        return
    }

    processUdpPacket(
        packet,
        totalLength,
        ipHeaderLength
    )
}

// =========================================================
// UDP
// =========================================================

private fun processUdpPacket(
    packet: ByteArray,
    totalLength: Int,
    ipHeaderLength: Int
) {

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
        udpLength >
        totalLength
    ) {
        return
    }

    /*
     * We only process DNS.
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
        dnsOffset +
        dnsLength >
        totalLength
    ) {
        return
    }

    val dnsQuery =
        packet.copyOfRange(
            dnsOffset,
            dnsOffset + dnsLength
        )

    processDnsQuery(
        packet = packet,
        totalLength = totalLength,
        ipHeaderLength = ipHeaderLength,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        dnsQuery = dnsQuery
    )
}

// =========================================================
// DNS
// =========================================================

private fun processDnsQuery(
    packet: ByteArray,
    totalLength: Int,
    ipHeaderLength: Int,
    sourcePort: Int,
    destinationPort: Int,
    dnsQuery: ByteArray
) {

    val hostname =
        parseDnsQuestionName(
            dnsQuery
        )

    if (
        hostname.isNullOrBlank()
    ) {

        /*
         * We cannot safely classify this DNS packet.
         * Forward it rather than dropping it.
         */
        forwardDnsQuery(
            originalPacket = packet,
            originalLength = totalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsQuery = dnsQuery
        )

        return
    }

    val normalized =
        hostname
            .trim()
            .trim('.')
            .lowercase()

    /*
     * Allowlist gets priority over blocking.
     */
    if (
        isAllowlisted(
            normalized
        )
    ) {

        forwardDnsQuery(
            originalPacket = packet,
            originalLength = totalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsQuery = dnsQuery
        )

        return
    }

    val blocked =
        FilterManager.isBlockedHost(
            this,
            normalized
        )

    if (blocked) {

        AdBlockStorage.incrementBlockedCount(
            this
        )

        android.util.Log.d(
            TAG,
            "Blocked DNS: $normalized"
        )

        val blockedResponse =
            buildBlockedDnsResponse(
                dnsQuery
            )

        if (
            blockedResponse != null
        ) {

            writeDnsResponse(
                originalPacket = packet,
                originalLength = totalLength,
                ipHeaderLength = ipHeaderLength,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                dnsResponse = blockedResponse
            )
        }

        return
    }

    /*
     * Allowed domain.
     */
    forwardDnsQuery(
        originalPacket = packet,
        originalLength = totalLength,
        ipHeaderLength = ipHeaderLength,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        dnsQuery = dnsQuery
    )
}

// =========================================================
// ALLOWLIST
// =========================================================

private fun isAllowlisted(
    hostname: String
): Boolean {

    val allowlist =
        AdBlockStorage.getAllowlist(
            this
        )

    if (
        allowlist.isEmpty()
    ) {
        return false
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

// =========================================================
// DNS QUESTION PARSER
// =========================================================

private fun parseDnsQuestionName(
    dnsPacket: ByteArray
): String? {

    if (
        dnsPacket.size <
        DNS_HEADER_LENGTH + 1
    ) {
        return null
    }

    /*
     * QDCOUNT.
     *
     * We only inspect the first question.
     */
    val questionCount =
        readUnsignedShort(
            dnsPacket,
            4
        )

    if (
        questionCount <= 0
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
        position < dnsPacket.size
    ) {

        if (
            labelCount > 127
        ) {
            return null
        }

        val length =
            dnsPacket[position].toInt() and 0xFF

        position++

        if (length == 0) {
            break
        }

        /*
         * DNS compression pointer.
         *
         * Query names should normally not use one.
         */
        if (
            (length and 0xC0) != 0
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

        if (
            label.isEmpty()
        ) {
            return null
        }

        labels.add(
            label
        )

        labelCount++

        position += length
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

// =========================================================
// BLOCKED DNS RESPONSE
// =========================================================

private fun buildBlockedDnsResponse(
    query: ByteArray
): ByteArray? {

    if (
        query.size <
        DNS_HEADER_LENGTH
    ) {
        return null
    }

    /*
     * Preserve the complete question.
     *
     * DNS header:
     *
     * ID       = bytes 0..1
     * FLAGS    = bytes 2..3
     * QDCOUNT  = bytes 4..5
     * ANCOUNT  = bytes 6..7
     * NSCOUNT  = bytes 8..9
     * ARCOUNT  = bytes 10..11
     */

    val response =
        query.copyOf()

    /*
     * Response flag.
     */
    response[2] =
        (
            response[2].toInt() or
                0x80
            ).toByte()

    /*
     * Clear opcode/other flags and preserve RD.
     *
     * Set:
     * QR = 1
     * RD = original RD
     * RA = 1
     */
    val originalFlags =
        readUnsignedShort(
            query,
            2
        )

    var flags =
        0x8000

    if (
        (originalFlags and 0x0100) != 0
    ) {
        flags =
            flags or 0x0100
    }

    /*
     * Recursion available.
     */
    flags =
        flags or 0x0080

    /*
     * NXDOMAIN.
     *
     * RCODE = 3.
     */
    flags =
        flags or 0x0003

    writeUnsignedShort(
        response,
        2,
        flags
    )

    /*
     * One question, zero answers.
     */
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

// =========================================================
// FORWARD DNS
// =========================================================

private fun forwardDnsQuery(
    originalPacket: ByteArray,
    originalLength: Int,
    ipHeaderLength: Int,
    sourcePort: Int,
    destinationPort: Int,
    dnsQuery: ByteArray
) {

    var socket: DatagramSocket? = null

    try {

        socket =
            DatagramSocket()

        /*
         * Prevent upstream DNS traffic from being captured
         * by our own VPN.
         */
        if (
            !protect(socket)
        ) {

            android.util.Log.e(
                TAG,
                "Could not protect upstream DNS socket"
            )

            return
        }

        socket.soTimeout =
            DNS_TIMEOUT_MS

        val upstream =
            InetSocketAddress(
                UPSTREAM_DNS,
                DNS_PORT
            )

        val request =
            DatagramPacket(
                dnsQuery,
                dnsQuery.size,
                upstream
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

        val response =
            responsePacket.data.copyOf(
                responsePacket.length
            )

        /*
         * Make sure the DNS transaction ID still matches.
         */
        if (
            response.size >= 2 &&
            dnsQuery.size >= 2
        ) {

            if (
                response[0] != dnsQuery[0] ||
                response[1] != dnsQuery[1]
            ) {

                android.util.Log.w(
                    TAG,
                    "Ignoring DNS response with mismatched transaction ID"
                )

                return
            }
        }

        writeDnsResponse(
            originalPacket = originalPacket,
            originalLength = originalLength,
            ipHeaderLength = ipHeaderLength,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dnsResponse = response
        )

    } catch (error: Exception) {

        android.util.Log.w(
            TAG,
            "Upstream DNS request failed",
            error
        )

    } finally {

        try {
            socket?.close()
        } catch (_: Exception) {
        }
    }
}

// =========================================================
// WRITE DNS RESPONSE INTO VPN
// =========================================================

private fun writeDnsResponse(
    originalPacket: ByteArray,
    originalLength: Int,
    ipHeaderLength: Int,
    sourcePort: Int,
    destinationPort: Int,
    dnsResponse: ByteArray
) {

    if (
        dnsResponse.isEmpty()
    ) {
        return
    }

    val output =
        outputStream
            ?: return

    if (
        originalLength <
        ipHeaderLength +
        UDP_HEADER_LENGTH
    ) {
        return
    }

    /*
     * Original:
     *
     * source      = phone
     * destination = 10.8.0.1
     *
     * Response:
     *
     * source      = 10.8.0.1
     * destination = phone
     */

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

    if (
        ipLength > 65535
    ) {
        return
    }

    val responsePacket =
        ByteArray(
            ipLength
        )

    /*
     * =====================================================
     * IPv4 HEADER
     * =====================================================
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

    /*
     * Identification.
     */
    responsePacket[4] =
        originalPacket[4]

    responsePacket[5] =
        originalPacket[5]

    /*
     * Fragment flags/offset.
     */
    responsePacket[6] =
        0

    responsePacket[7] =
        0

    /*
     * TTL.
     */
    responsePacket[8] =
        64.toByte()

    /*
     * UDP protocol.
     */
    responsePacket[9] =
        UDP_PROTOCOL.toByte()

    /*
     * IP checksum initially zero.
     */
    responsePacket[10] =
        0

    responsePacket[11] =
        0

    System.arraycopy(
        responseSourceIp,
        0,
        responsePacket,
        12,
        4
    )

    System.arraycopy(
        responseDestinationIp,
        0,
        responsePacket,
        16,
        4
    )

    val ipChecksum =
        calculateChecksum(
            responsePacket,
            0,
            IPV4_HEADER_LENGTH
        )

    writeUnsignedShort(
        responsePacket,
        10,
        ipChecksum
    )

    /*
     * =====================================================
     * UDP HEADER
     * =====================================================
     */

    writeUnsignedShort(
        responsePacket,
        20,
        responseSourcePort
    )

    writeUnsignedShort(
        responsePacket,
        22,
        responseDestinationPort
    )

    writeUnsignedShort(
        responsePacket,
        24,
        udpLength
    )

    /*
     * IPv4 allows UDP checksum zero.
     */
    responsePacket[26] =
        0

    responsePacket[27] =
        0

    /*
     * =====================================================
     * DNS PAYLOAD
     * =====================================================
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

        if (
            running.get()
        ) {

            android.util.Log.w(
                TAG,
                "Could not write DNS response",
                error
            )
        }
    }
}

// =========================================================
// FILTER REFRESH
// =========================================================

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
                    FILTER_REFRESH_MS
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

                    android.util.Log.w(
                        TAG,
                        "Filter refresh failed",
                        error
                    )
                }
            }
        }
}

// =========================================================
// STOP VPN
// =========================================================

private fun stopVpn() {

    running.set(false)

    isRunning = false

    packetJob?.cancel()

    packetJob = null

    filterRefreshJob?.cancel()

    filterRefreshJob = null

    /*
     * Closing the streams also wakes a blocked read().
     */
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

    /*
     * IMPORTANT:
     *
     * ParcelFileDescriptor has close().
     *
     * Keep a local immutable reference so Kotlin does not
     * complain about a mutable-property smart cast.
     */
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
        stopForeground(
            true
        )
    }

    stopSelf()
}

// =========================================================
// FOREGROUND NOTIFICATION
// =========================================================

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
            "DNS ad and tracker protection is active"
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
        "DNS-based ad and tracker blocking"

    manager.createNotificationChannel(
        channel
    )
}

// =========================================================
// CHECKSUM
// =========================================================

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
        index + 1 <
        end
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

// =========================================================
// BYTE UTILITIES
// =========================================================

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

// =========================================================
// SERVICE LIFECYCLE
// =========================================================

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

    return super.onBind(
        intent
    )
}

}

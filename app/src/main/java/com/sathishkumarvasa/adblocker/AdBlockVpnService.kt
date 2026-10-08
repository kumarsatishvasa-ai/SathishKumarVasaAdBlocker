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
import java.net.Socket 
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockVpnService : VpnService() {

companion object {

const val ACTION_START = "com.sathishkumarvasa.adblocker.START"

const val ACTION_STOP = "com.sathishkumarvasa.adblocker.STOP"

private const val TAG = "AdBlockVpnService"

private const val CHANNELID = "adblocker_vpn"

private const val NOTIFICATION_ID = 1001

/* * Private VPN network. */ private const val VPN_ADDRESS = "10.8.0.2"

private const val VPN_PREFIX = 24

/* * DNS address exposed inside the VPN. */ private const val DNS_ADDRESS = "10.8.0.1"

/* * Upstream DNS. * * This is deliberately protected with VpnService.protect() * so the request does not return through our VPN. */ private const val UPSTREAM_DNS = "1.1.1.1"

private const val DNS_PORT = 53

private const val MTU = 1500

private const val MAXPACKETSIZE = 32767

private const val MAXDNSPACKET_SIZE = 4096

private const val DNSTIMEOUTMS = 4000

private const val TCPDNSTIMEOUT_MS = 5000

private const val IPV4HEADERLENGTH = 20

private const val UDPHEADERLENGTH = 8

private const val TCPMINHEADER_LENGTH = 20

private const val DNSHEADERLENGTH = 12

private const val UDP_PROTOCOL = 17

private const val TCP_PROTOCOL = 6

private const val FILTERREFRESHMS = 12L * 60L * 60L * 1000L

@Volatile var isRunning: Boolean = false private set }

private var vpnInterface: ParcelFileDescriptor? = null

private var inputStream: FileInputStream? = null

private var outputStream: FileOutputStream? = null

private val serviceScope = CoroutineScope( SupervisorJob() + Dispatchers.IO )

private var packetJob: Job? = null

private var filterJob: Job? = null

private val running = AtomicBoolean(false)

@Volatile private var dnsQueryCount = 0

@Volatile private var blockedDnsCount = 0

@Volatile private var forwardedDnsCount = 0

// ============================================================ // SERVICE // ============================================================

override fun onCreate() { super.onCreate()

createNotificationChannel() }

override fun onStartCommand( intent: Intent?, flags: Int, startId: Int ): Int {

when (intent?.action) {

ACTIONSTOP -> { stopVpn() return STARTNOT_STICKY }

ACTION_START -> { startVpn() }

else -> { startVpn() } }

return START_STICKY }

// ============================================================ // START VPN // ============================================================

private fun startVpn() {

if (running.get()) { return }

dnsQueryCount = 0 blockedDnsCount = 0 forwardedDnsCount = 0

try {

startForeground( NOTIFICATION_ID, createNotification( "Starting DNS protection..." ) )

/* * IMPORTANT: * * This is a DNS-only VPN. * * We deliberately DO NOT add: * * addRoute("0.0.0.0", 0) * * because this service does not implement * complete forwarding of all Internet traffic. * * Only DNS traffic is sent into the VPN. */ val builder = Builder() .setSession( getString(R.string.appname) ) .setMtu(MTU) .addAddress( VPNADDRESS, VPNPREFIX ) .addDnsServer( DNSADDRESS ) .addRoute( DNS_ADDRESS, 32 )

/* * Prevent our own application traffic from * entering its own VPN. */ try {

builder.addDisallowedApplication( packageName )

} catch (e: Exception) {

android.util.Log.w( TAG, "Could not exclude own package", e ) }

val established = builder.establish()

if (established == null) {

updateNotification( "Could not establish VPN" )

stopVpn()

return }

vpnInterface = established

inputStream = FileInputStream( established.fileDescriptor )

outputStream = FileOutputStream( established.fileDescriptor )

running.set(true)

isRunning = true

updateDiagnosticNotification()

startPacketLoop()

startFilterRefresh()

android.util.Log.i( TAG, "DNS-only VPN started" )

} catch (e: Exception) {

android.util.Log.e( TAG, "Could not start VPN", e )

updateNotification( "VPN error: ${e.message ?: "unknown"}" )

stopVpn() } }

// ============================================================ // PACKET LOOP // ============================================================

private fun startPacketLoop() {

packetJob?.cancel()

packetJob = serviceScope.launch {

val buffer = ByteArray( MAXPACKETSIZE )

while ( isActive && running.get() ) {

val input = inputStream ?: break

try {

val count = input.read(buffer)

if (count <= 0) { continue }

val packet = buffer.copyOf(count)

processPacket(packet)

} catch (e: Exception) {

if (running.get()) {

android.util.Log.w( TAG, "VPN read error", e ) }

break } } } }

// ============================================================ // IP PACKET // ============================================================

private fun processPacket( packet: ByteArray ) {

if ( packet.size < IPV4HEADERLENGTH ) { return }

val version = (packet[0].toInt() ushr 4) and 0x0F

/* * This implementation handles IPv4. */ if (version != 4) { return }

val headerLength = (packet[0].toInt() and 0x0F) * 4

if ( headerLength < IPV4HEADERLENGTH || headerLength > packet.size ) { return }

val totalLength = readUnsignedShort( packet, 2 )

if ( totalLength < headerLength || totalLength > packet.size ) { return }

val protocol = packet[9].toInt() and 0xFF

when (protocol) {

UDP_PROTOCOL -> {

processUdpPacket( packet, totalLength, headerLength ) }

TCP_PROTOCOL -> {

processTcpPacket( packet, totalLength, headerLength ) }

else -> { /* * Not DNS. * * We intentionally do not interfere with it. */ } } }

// ============================================================ // UDP // ============================================================

private fun processUdpPacket( packet: ByteArray, totalLength: Int, ipHeaderLength: Int ) {

val udpOffset = ipHeaderLength

if ( totalLength < udpOffset + UDPHEADERLENGTH ) { return }

val sourcePort = readUnsignedShort( packet, udpOffset )

val destinationPort = readUnsignedShort( packet, udpOffset + 2 )

val udpLength = readUnsignedShort( packet, udpOffset + 4 )

if ( udpLength < UDPHEADERLENGTH ) { return }

if ( udpOffset + udpLength > totalLength ) { return }

/* * DNS request. */ if ( destinationPort == DNS_PORT ) {

val dnsOffset = udpOffset + UDPHEADERLENGTH

val dnsLength = udpLength - UDPHEADERLENGTH

if ( dnsLength < DNSHEADERLENGTH ) { return }

if ( dnsOffset + dnsLength > totalLength ) { return }

val dnsQuery = packet.copyOfRange( dnsOffset, dnsOffset + dnsLength )

handleDnsQuery( originalPacket = packet, originalLength = totalLength, ipHeaderLength = ipHeaderLength, sourcePort = sourcePort, destinationPort = destinationPort, dnsQuery = dnsQuery ) } }

// ============================================================ // TCP DNS // ============================================================

private fun processTcpPacket( packet: ByteArray, totalLength: Int, ipHeaderLength: Int ) {

val tcpOffset = ipHeaderLength

if ( totalLength < tcpOffset + TCPMINHEADER_LENGTH ) { return }

val sourcePort = readUnsignedShort( packet, tcpOffset )

val destinationPort = readUnsignedShort( packet, tcpOffset + 2 )

/* * Only DNS-over-TCP destination port 53. */ if ( destinationPort != DNS_PORT ) { return }

val dataOffset = ( ((packet[tcpOffset + 12] .toInt() and 0xF0) ushr 4) * 4 )

if ( dataOffset < TCPMINHEADER_LENGTH ) { return }

if ( tcpOffset + dataOffset > totalLength ) { return }

val payloadOffset = tcpOffset + dataOffset

val payloadLength = totalLength - payloadOffset

if (payloadLength < 2) { return }

/* * DNS-over-TCP has a two-byte length prefix. */ val dnsLength = readUnsignedShort( packet, payloadOffset )

if ( dnsLength <= 0 || dnsLength > MAXDNSPACKET_SIZE ) { return }

if ( payloadOffset + 2 + dnsLength > totalLength ) { return }

val dnsQuery = packet.copyOfRange( payloadOffset + 2, payloadOffset + 2 + dnsLength )

/* * DNS-over-TCP is less common on Android. * * We process it for filtering but use UDP upstream. */ handleDnsQuery( originalPacket = packet, originalLength = totalLength, ipHeaderLength = ipHeaderLength, sourcePort = sourcePort, destinationPort = destinationPort, dnsQuery = dnsQuery ) }

// ============================================================ // DNS QUERY // ============================================================

private fun handleDnsQuery( originalPacket: ByteArray, originalLength: Int, ipHeaderLength: Int, sourcePort: Int, destinationPort: Int, dnsQuery: ByteArray ) {

dnsQueryCount++

val hostname = parseDnsQuestionName( dnsQuery )

if (hostname.isNullOrBlank()) {

/* * Cannot parse it. * * Fail open rather than breaking Internet access. */ forwardedDnsCount++

forwardDnsQuery( originalPacket, originalLength, ipHeaderLength, sourcePort, destinationPort, dnsQuery )

updateDiagnosticNotification()

return }

val normalized = hostname .trim() .trim('.') .lowercase()

android.util.Log.d( TAG, "DNS: $normalized" )

/* * Allowlist first. */ if ( isAllowlisted(normalized) ) {

forwardedDnsCount++

forwardDnsQuery( originalPacket, originalLength, ipHeaderLength, sourcePort, destinationPort, dnsQuery )

updateDiagnosticNotification()

return }

val blocked = try {

FilterManager.isBlockedHost( this, normalized )

} catch (e: Exception) {

android.util.Log.e( TAG, "Filter check failed", e )

/* * Fail open. */ false }

if (blocked) {

blockedDnsCount++

try {

AdBlockStorage.incrementBlockedCount( this )

} catch (_: Exception) { }

android.util.Log.d( TAG, "BLOCKED: $normalized" )

val response = buildBlockedDnsResponse( dnsQuery )

if (response != null) {

writeDnsResponse( originalPacket, originalLength, ipHeaderLength, sourcePort, destinationPort, response ) }

} else {

forwardedDnsCount++

android.util.Log.d( TAG, "FORWARDED: $normalized" )

forwardDnsQuery( originalPacket, originalLength, ipHeaderLength, sourcePort, destinationPort, dnsQuery ) }

updateDiagnosticNotification() }

// ============================================================ // ALLOWLIST // ============================================================

private fun isAllowlisted( hostname: String ): Boolean {

val allowlist = try {

AdBlockStorage.getAllowlist( this )

} catch (_: Exception) {

emptySet() }

if (allowlist.isEmpty()) { return false }

val normalized = allowlist .map { it.trim() .trim('.') .lowercase() } .toSet()

if ( normalized.contains(hostname) ) { return true }

var current = hostname

while (true) {

val dot = current.indexOf('.')

if (dot < 0) { break }

current = current.substring( dot + 1 )

if ( normalized.contains(current) ) { return true } }

return false }

// ============================================================ // DNS QUESTION PARSER // ============================================================

private fun parseDnsQuestionName( dnsPacket: ByteArray ): String? {

if ( dnsPacket.size < DNSHEADERLENGTH + 1 ) { return null }

val questionCount = readUnsignedShort( dnsPacket, 4 )

if (questionCount <= 0) { return null }

var position = DNSHEADERLENGTH

val labels = mutableListOf<String>()

while ( position < dnsPacket.size ) {

val length = dnsPacket[position] .toInt() and 0xFF

position++

if (length == 0) { break }

/* * Compression is not expected in the question name. */ if ( (length and 0xC0) != 0 ) { return null }

if (length > 63) { return null }

if ( position + length > dnsPacket.size ) { return null }

val label = dnsPacket .copyOfRange( position, position + length ) .toString( Charsets.US_ASCII )

if (label.isEmpty()) { return null }

labels.add(label)

position += length

if (labels.size > 127) { return null } }

if (labels.isEmpty()) { return null }

return labels .joinToString(".") .lowercase() }

// ============================================================ // BLOCKED DNS RESPONSE // ============================================================

private fun buildBlockedDnsResponse( query: ByteArray ): ByteArray? {

if ( query.size < DNSHEADERLENGTH ) { return null }

val response = query.copyOf()

val originalFlags = readUnsignedShort( query, 2 )

/* * QR = response */ var flags = 0x8000

/* * Preserve RD. */ if ( originalFlags and 0x0100 != 0 ) { flags = flags or 0x0100 }

/* * RA */ flags = flags or 0x0080

/* * NXDOMAIN */ flags = flags or 0x0003

writeUnsignedShort( response, 2, flags )

/* * One question. */ writeUnsignedShort( response, 4, 1 )

/* * No answers. */ writeUnsignedShort( response, 6, 0 )

/* * Authority. */ writeUnsignedShort( response, 8, 0 )

/* * Additional. */ writeUnsignedShort( response, 10, 0 )

return response }

// ============================================================ // FORWARD DNS // ============================================================

private fun forwardDnsQuery( originalPacket: ByteArray, originalLength: Int, ipHeaderLength: Int, sourcePort: Int, destinationPort: Int, dnsQuery: ByteArray ) {

var socket: DatagramSocket? = null

try {

socket = DatagramSocket()

/* * VERY IMPORTANT. * * Prevent the upstream DNS socket from being * captured by our own VPN. */ if (!protect(socket)) {

android.util.Log.e( TAG, "Could not protect DNS socket" )

return }

socket.soTimeout = DNSTIMEOUTMS

val request = DatagramPacket( dnsQuery, dnsQuery.size, InetSocketAddress( UPSTREAMDNS, DNSPORT ) )

socket.send(request)

val responseBuffer = ByteArray( MAXDNSPACKET_SIZE )

val responsePacket = DatagramPacket( responseBuffer, responseBuffer.size )

socket.receive( responsePacket )

if ( responsePacket.length <= 0 ) { return }

val response = responsePacket.data.copyOf( responsePacket.length )

/* * Verify transaction ID. */ if ( dnsQuery.size >= 2 && response.size >= 2 ) {

val queryId = ( ((dnsQuery[0].toInt() and 0xFF) shl 8) or (dnsQuery[1].toInt() and 0xFF) )

val responseId = ( ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF) )

if ( queryId != responseId ) {

android.util.Log.w( TAG, "DNS transaction ID mismatch" )

return } }

writeDnsResponse( originalPacket, originalLength, ipHeaderLength, sourcePort, destinationPort, response )

} catch (e: Exception) {

android.util.Log.w( TAG, "DNS forwarding failed", e )

} finally {

try { socket?.close() } catch (_: Exception) { } } }

// ============================================================ // WRITE DNS RESPONSE // ============================================================

private fun writeDnsResponse( originalPacket: ByteArray, originalLength: Int, ipHeaderLength: Int, sourcePort: Int, destinationPort: Int, dnsResponse: ByteArray ) {

val output = outputStream ?: return

if (dnsResponse.isEmpty()) { return }

if ( originalPacket.size < IPV4HEADERLENGTH ) { return }

val originalSourceIp = originalPacket.copyOfRange( 12, 16 )

val originalDestinationIp = originalPacket.copyOfRange( 16, 20 )

val udpLength = UDPHEADERLENGTH + dnsResponse.size

val ipLength = IPV4HEADERLENGTH + udpLength

if ( ipLength > 65535 ) { return }

val responsePacket = ByteArray(ipLength)

/* * IPv4. */ responsePacket[0] = 0x45.toByte()

responsePacket[1] = 0

writeUnsignedShort( responsePacket, 2, ipLength )

/* * Copy identification. */ responsePacket[4] = originalPacket[4]

responsePacket[5] = originalPacket[5]

/* * No fragmentation. */ responsePacket[6] = 0

responsePacket[7] = 0

/* * TTL. */ responsePacket[8] = 64

responsePacket[9] = UDP_PROTOCOL.toByte()

responsePacket[10] = 0

responsePacket[11] = 0

/* * Reverse source/destination. */ System.arraycopy( originalDestinationIp, 0, responsePacket, 12, 4 )

System.arraycopy( originalSourceIp, 0, responsePacket, 16, 4 )

/* * IPv4 checksum. */ val checksum = calculateChecksum( responsePacket, 0, IPV4HEADERLENGTH )

writeUnsignedShort( responsePacket, 10, checksum )

/* * UDP source = original DNS destination. */ writeUnsignedShort( responsePacket, 20, destinationPort )

/* * UDP destination = original source. */ writeUnsignedShort( responsePacket, 22, sourcePort )

writeUnsignedShort( responsePacket, 24, udpLength )

/* * UDP checksum zero is valid for IPv4. */ responsePacket[26] = 0

responsePacket[27] = 0

/* * DNS data. */ System.arraycopy( dnsResponse, 0, responsePacket, IPV4HEADERLENGTH + UDPHEADERLENGTH, dnsResponse.size )

try {

output.write( responsePacket )

output.flush()

} catch (e: Exception) {

if (running.get()) {

android.util.Log.w( TAG, "Could not write DNS response", e ) } } }

// ============================================================ // FILTER REFRESH // ============================================================

private fun startFilterRefresh() {

filterJob?.cancel()

filterJob = serviceScope.launch {

try {

FilterManager.updateFilters( this@AdBlockVpnService )

} catch (e: Exception) {

android.util.Log.w( TAG, "Initial filter update failed", e ) }

while ( isActive && running.get() ) {

delay( FILTERREFRESHMS )

if (!running.get()) { break }

try {

FilterManager.updateFilters( this@AdBlockVpnService )

} catch (e: Exception) {

android.util.Log.w( TAG, "Filter refresh failed", e ) } } } }

// ============================================================ // NOTIFICATION // ============================================================

private fun updateDiagnosticNotification() {

if (!running.get()) { return }

updateNotification( "DNS: $dnsQueryCount • " + "Blocked: $blockedDnsCount • " + "Forwarded: $forwardedDnsCount" ) }

private fun updateNotification( text: String ) {

try {

val manager = getSystemService( NotificationManager::class.java )

manager.notify( NOTIFICATION_ID, createNotification(text) )

} catch (e: Exception) {

android.util.Log.w( TAG, "Notification update failed", e ) } }

private fun createNotification( text: String ): Notification {

return NotificationCompat .Builder( this, CHANNELID ) .setContentTitle( getString(R.string.appname) ) .setContentText(text) .setSmallIcon( android.R.drawable.icsecure ) .setOngoing(true) .setCategory( NotificationCompat.CATEGORYSERVICE ) .setPriority( NotificationCompat.PRIORITY_LOW ) .build() }

private fun createNotificationChannel() {

if ( Build.VERSION.SDKINT < Build.VERSIONCODES.O ) { return }

val manager = getSystemService( NotificationManager::class.java )

val channel = NotificationChannel( CHANNELID, "Ad Blocker VPN", NotificationManager.IMPORTANCELOW )

channel.description = "DNS ad and tracker blocking"

manager.createNotificationChannel( channel ) }

// ============================================================ // CHECKSUM // ============================================================

private fun calculateChecksum( data: ByteArray, offset: Int, length: Int ): Int {

var sum = 0L

var index = offset

val end = offset + length

while ( index + 1 < end ) {

val word = ( ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF) )

sum += word.toLong()

while ( (sum ushr 16) != 0L ) {

sum = (sum and 0xFFFFL) + (sum ushr 16) }

index += 2 }

if (index < end) {

sum += ( (data[index].toInt() and 0xFF) .toLong() shl 8 ) }

while ( (sum ushr 16) != 0L ) {

sum = (sum and 0xFFFFL) + (sum ushr 16) }

return ( sum.inv() and 0xFFFFL ).toInt() }

// ============================================================ // BYTE HELPERS // ============================================================

private fun readUnsignedShort( data: ByteArray, offset: Int ): Int {

if ( offset < 0 || offset + 1 >= data.size ) { return 0 }

return ( ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF) ) }

private fun writeUnsignedShort( data: ByteArray, offset: Int, value: Int ) {

if ( offset < 0 || offset + 1 >= data.size ) { return }

data[offset] = ((value ushr 8) and 0xFF) .toByte()

data[offset + 1] = (value and 0xFF) .toByte() }

// ============================================================ // STOP // ============================================================

private fun stopVpn() {

running.set(false)

isRunning = false

packetJob?.cancel() packetJob = null

filterJob?.cancel() filterJob = null

try { inputStream?.close() } catch (_: Exception) { }

inputStream = null

try { outputStream?.close() } catch (_: Exception) { }

outputStream = null

val descriptor = vpnInterface

vpnInterface = null

try { descriptor?.close() } catch (_: Exception) { }

if ( Build.VERSION.SDKINT >= Build.VERSIONCODES.N ) {

stopForeground( STOPFOREGROUNDREMOVE )

} else {

@Suppress("DEPRECATION") stopForeground(true) }

stopSelf() }

// ============================================================ // VPN REVOKED // ============================================================

override fun onRevoke() {

stopVpn()

super.onRevoke() }

// ============================================================ // DESTROY // ============================================================

override fun onDestroy() {

stopVpn()

serviceScope.cancel()

super.onDestroy() }

override fun onBind( intent: Intent? ): IBinder? {

return super.onBind(intent) } } 

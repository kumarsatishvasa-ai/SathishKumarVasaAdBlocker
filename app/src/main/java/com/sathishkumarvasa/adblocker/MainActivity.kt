:::writing{variant="document" id="42617" title="MainActivity.kt"} package com.sathishkumarvasa.adblocker

import android.content.Intent import android.net.VpnService import android.os.Bundle import android.widget.Toast import androidx.activity.ComponentActivity import androidx.activity.compose.setContent import androidx.activity.result.contract.ActivityResultContracts import androidx.compose.foundation.layout.Arrangement import androidx.compose.foundation.layout.Column import androidx.compose.foundation.layout.Row import androidx.compose.foundation.layout.Spacer import androidx.compose.foundation.layout.fillMaxSize import androidx.compose.foundation.layout.fillMaxWidth import androidx.compose.foundation.layout.height import androidx.compose.foundation.layout.padding import androidx.compose.foundation.rememberScrollState import androidx.compose.foundation.verticalScroll import androidx.compose.material3.Button import androidx.compose.material3.Card import androidx.compose.material3.MaterialTheme import androidx.compose.material3.OutlinedButton import androidx.compose.material3.Surface import androidx.compose.material3.Switch import androidx.compose.material3.Text import androidx.compose.runtime.LaunchedEffect import androidx.compose.runtime.getValue import androidx.compose.runtime.mutableStateOf import androidx.compose.runtime.remember import androidx.compose.runtime.setValue import androidx.compose.ui.Alignment import androidx.compose.ui.Modifier import androidx.compose.ui.unit.dp import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {

private var vpnPermissionGranted = false

private val vpnPermissionLauncher = registerForActivityResult( ActivityResultContracts.StartActivityForResult() ) { result ->

if (result.resultCode == RESULT_OK) {

vpnPermissionGranted = true

startAdBlocker()

} else {

Toast.makeText( this, "VPN permission was not granted", Toast.LENGTH_LONG ).show() } }

override fun onCreate( savedInstanceState: Bundle? ) { super.onCreate(savedInstanceState)

setContent {

MaterialTheme {

Surface( modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background ) {

AdBlockerScreen() } } } }

// ========================================================= // VPN PERMISSION // =========================================================

private fun requestVpnPermission() {

val prepareIntent = VpnService.prepare(this)

if (prepareIntent != null) {

vpnPermissionLauncher.launch( prepareIntent )

} else {

vpnPermissionGranted = true

startAdBlocker() } }

// ========================================================= // START // =========================================================

private fun startAdBlocker() {

try {

/* * IMPORTANT: * * The service is AdBlockVpnService. * * Do NOT use DnsVpnService here. */ val intent = Intent( this, AdBlockVpnService::class.java ).apply {

action = AdBlockVpnService.ACTION_START }

/* * Android 8+ requires a foreground * service for this type of long-running work. */ startForegroundService(intent)

Toast.makeText( this, "Starting DNS ad blocker...", Toast.LENGTH_SHORT ).show()

} catch (error: Exception) {

Toast.makeText( this, "Could not start VPN: ${error.message}", Toast.LENGTH_LONG ).show() } }

// ========================================================= // STOP // =========================================================

private fun stopAdBlocker() {

try {

val intent = Intent( this, AdBlockVpnService::class.java ).apply {

action = AdBlockVpnService.ACTION_STOP }

startService(intent)

Toast.makeText( this, "Stopping ad blocker...", Toast.LENGTH_SHORT ).show()

} catch (error: Exception) {

Toast.makeText( this, "Could not stop VPN: ${error.message}", Toast.LENGTH_LONG ).show() } }

// ========================================================= // SCREEN // =========================================================

@androidx.compose.runtime.Composable private fun AdBlockerScreen() {

var enabled by remember {

mutableStateOf( AdBlockVpnService.isRunning ) }

/* * Periodically synchronize the UI with * the actual VPN service state. */ LaunchedEffect(Unit) {

while (true) {

enabled = AdBlockVpnService.isRunning

delay(500) } }

Column( modifier = Modifier .fillMaxSize() .verticalScroll( rememberScrollState() ) .padding(24.dp),

verticalArrangement = Arrangement.Top,

horizontalAlignment = Alignment.CenterHorizontally ) {

Spacer( modifier = Modifier.height(24.dp) )

Text( text = "DNS Ad Blocker", style = MaterialTheme .typography .headlineMedium )

Spacer( modifier = Modifier.height(8.dp) )

Text( text = "Block ads and trackers using a local DNS VPN.", style = MaterialTheme .typography .bodyMedium )

Spacer( modifier = Modifier.height(32.dp) )

// ================================================= // STATUS CARD // =================================================

Card( modifier = Modifier.fillMaxWidth() ) {

Column( modifier = Modifier.padding(20.dp) ) {

Text( text = if (enabled) { "Protection enabled" } else { "Protection disabled" },

style = MaterialTheme .typography .titleLarge )

Spacer( modifier = Modifier.height(8.dp) )

Text( text = if (enabled) { "DNS filtering VPN is running." } else { "DNS filtering VPN is stopped." },

style = MaterialTheme .typography .bodyMedium )

Spacer( modifier = Modifier.height(20.dp) )

Row( modifier = Modifier.fillMaxWidth(),

horizontalArrangement = Arrangement.SpaceBetween,

verticalAlignment = Alignment.CenterVertically ) {

Text( text = "Ad blocking" )

Switch( checked = enabled,

onCheckedChange = { checked ->

if (checked) {

requestVpnPermission()

} else {

stopAdBlocker() } } ) } } }

Spacer( modifier = Modifier.height(24.dp) )

// ================================================= // START BUTTON // =================================================

Button( modifier = Modifier.fillMaxWidth(),

enabled = !enabled,

onClick = {

requestVpnPermission() } ) {

Text( text = "Start Ad Blocker" ) }

Spacer( modifier = Modifier.height(12.dp) )

// ================================================= // STOP BUTTON // =================================================

OutlinedButton( modifier = Modifier.fillMaxWidth(),

enabled = enabled,

onClick = {

stopAdBlocker() } ) {

Text( text = "Stop Ad Blocker" ) }

Spacer( modifier = Modifier.height(32.dp) )

// ================================================= // INFORMATION // =================================================

Card( modifier = Modifier.fillMaxWidth() ) {

Column( modifier = Modifier.padding(20.dp) ) {

Text( text = "How it works",

style = MaterialTheme .typography .titleMedium )

Spacer( modifier = Modifier.height(8.dp) )

Text( text = "The app creates an Android VPN interface " + "and filters DNS requests locally. " + "Allowed DNS requests are forwarded to the " + "upstream DNS resolver. Blocked domains receive " + "a DNS blocking response." ) } }

Spacer( modifier = Modifier.height(24.dp) )

Text( text = "Version 1.0.0",

style = MaterialTheme .typography .bodySmall ) } }

// ========================================================= // ACTIVITY RESUME // =========================================================

override fun onResume() {

super.onResume()

/* * Re-check whether VPN permission is available. */ vpnPermissionGranted = VpnService.prepare(this) == null } }

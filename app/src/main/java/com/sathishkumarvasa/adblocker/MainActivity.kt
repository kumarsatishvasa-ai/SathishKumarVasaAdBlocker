package com.sathishkumarvasa.adblocker

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->

            if (result.resultCode == RESULT_OK) {
                startAdBlocker()
            } else {
                Toast.makeText(
                    this,
                    "VPN permission was not granted",
                    Toast.LENGTH_LONG
                ).show()
            }
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { granted ->

            if (granted) {
                requestVpnPermission()
            } else {
                Toast.makeText(
                    this,
                    "Notification permission denied. VPN can still be requested.",
                    Toast.LENGTH_LONG
                ).show()

                requestVpnPermission()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AdBlockerScreen()
                }
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {

            if (
                checkSelfPermission(
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {

                notificationPermissionLauncher.launch(
                    Manifest.permission.POST_NOTIFICATIONS
                )

                return
            }
        }

        requestVpnPermission()
    }

    private fun requestVpnPermission() {

        try {

            val intent =
                VpnService.prepare(this)

            if (intent != null) {

                vpnPermissionLauncher.launch(intent)

            } else {

                startAdBlocker()
            }

        } catch (error: Exception) {

            Toast.makeText(
                this,
                "VPN permission error: ${error.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun startAdBlocker() {

        try {

            val intent =
                Intent(
                    this,
                    AdBlockVpnService::class.java
                ).apply {
                    action =
                        AdBlockVpnService.ACTION_START
                }

            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.O
            ) {

                startForegroundService(intent)

            } else {

                startService(intent)
            }

            Toast.makeText(
                this,
                "Starting DNS ad blocker...",
                Toast.LENGTH_SHORT
            ).show()

        } catch (error: Exception) {

            Toast.makeText(
                this,
                "Failed to start VPN: ${error.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun stopAdBlocker() {

        try {

            val intent =
                Intent(
                    this,
                    AdBlockVpnService::class.java
                ).apply {
                    action =
                        AdBlockVpnService.ACTION_STOP
                }

            startService(intent)

            Toast.makeText(
                this,
                "Ad blocker stopped",
                Toast.LENGTH_SHORT
            ).show()

        } catch (error: Exception) {

            Toast.makeText(
                this,
                "Failed to stop VPN: ${error.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    @Composable
    private fun AdBlockerScreen() {

        var enabled by remember {
            mutableStateOf(
                AdBlockVpnService.isRunning
            )
        }

        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .verticalScroll(
                        rememberScrollState()
                    )
                    .padding(24.dp),

            verticalArrangement =
                Arrangement.Top,

            horizontalAlignment =
                Alignment.CenterHorizontally
        ) {

            Spacer(
                modifier =
                    Modifier.height(24.dp)
            )

            Text(
                text = "DNS Ad Blocker",
                style =
                    MaterialTheme.typography.headlineMedium
            )

            Spacer(
                modifier =
                    Modifier.height(8.dp)
            )

            Text(
                text =
                    "Block advertisements and trackers using a local DNS VPN.",
                style =
                    MaterialTheme.typography.bodyMedium
            )

            Spacer(
                modifier =
                    Modifier.height(32.dp)
            )

            Card(
                modifier =
                    Modifier.fillMaxWidth()
            ) {

                Column(
                    modifier =
                        Modifier.padding(20.dp)
                ) {

                    Text(
                        text =
                            if (enabled) {
                                "Protection enabled"
                            } else {
                                "Protection disabled"
                            },

                        style =
                            MaterialTheme.typography.titleLarge
                    )

                    Spacer(
                        modifier =
                            Modifier.height(8.dp)
                    )

                    Text(
                        text =
                            if (enabled) {
                                "DNS filtering VPN is running."
                            } else {
                                "The DNS filtering VPN is stopped."
                            },

                        style =
                            MaterialTheme.typography.bodyMedium
                    )

                    Spacer(
                        modifier =
                            Modifier.height(20.dp)
                    )

                    Row(
                        modifier =
                            Modifier.fillMaxWidth(),

                        horizontalArrangement =
                            Arrangement.SpaceBetween,

                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        Text(
                            text = "Ad blocking"
                        )

                        Switch(
                            checked = enabled,

                            onCheckedChange = { checked ->

                                if (checked) {

                                    requestNotificationPermissionIfNeeded()

                                } else {

                                    stopAdBlocker()
                                    enabled = false
                                }
                            }
                        )
                    }
                }
            }

            Spacer(
                modifier =
                    Modifier.height(24.dp)
            )

            Button(
                modifier =
                    Modifier.fillMaxWidth(),

                onClick = {

                    requestNotificationPermissionIfNeeded()

                    enabled = true
                }
            ) {
                Text("Start Ad Blocker")
            }

            Spacer(
                modifier =
                    Modifier.height(12.dp)
            )

            OutlinedButton(
                modifier =
                    Modifier.fillMaxWidth(),

                onClick = {

                    stopAdBlocker()

                    enabled = false
                }
            ) {
                Text("Stop Ad Blocker")
            }

            Spacer(
                modifier =
                    Modifier.height(32.dp)
            )

            Card(
                modifier =
                    Modifier.fillMaxWidth()
            ) {

                Column(
                    modifier =
                        Modifier.padding(20.dp)
                ) {

                    Text(
                        text = "How it works",

                        style =
                            MaterialTheme.typography.titleMedium
                    )

                    Spacer(
                        modifier =
                            Modifier.height(8.dp)
                    )

                    Text(
                        text =
                            "The app creates an Android VPN interface and intercepts DNS requests. Blocked domains receive an NXDOMAIN response. Allowed DNS requests are forwarded to the upstream DNS server."
                    )
                }
            }

            Spacer(
                modifier =
                    Modifier.height(24.dp)
            )

            Text(
                text = "Version 1.0.0",

                style =
                    MaterialTheme.typography.bodySmall
            )
        }
    }
}

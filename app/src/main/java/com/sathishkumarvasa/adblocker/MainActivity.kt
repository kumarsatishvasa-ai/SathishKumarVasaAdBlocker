package com.sathishkumarvasa.adblocker

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

class MainActivity : ComponentActivity() {

    private lateinit var preferences: AppPreferences

    /*
     * Android VPN permission result.
     */
    private val vpnPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) {

            if (it.resultCode == RESULT_OK) {
                startVpnService()
            }
        }

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        preferences =
            AppPreferences(
                applicationContext
            )

        setContentView(
            R.layout.activity_main
        )

        setupViews()

        /*
         * If the app was already enabled when the
         * Activity was recreated, refresh the UI.
         */
        updateUi()
    }

    private fun setupViews() {

        /*
         * These IDs should exist in activity_main.xml.
         *
         * If your existing XML uses different IDs,
         * change the IDs here to match it.
         */

        val enableButton =
            findViewById<android.view.View>(
                R.id.enableButton
            )

        val disableButton =
            findViewById<android.view.View>(
                R.id.disableButton
            )

        enableButton.setOnClickListener {

            enableAdBlocker()
        }

        disableButton.setOnClickListener {

            disableAdBlocker()
        }
    }

    private fun enableAdBlocker() {

        /*
         * Store enabled state first.
         */
        preferences.setEnabled(true)

        /*
         * Android requires explicit user approval before
         * an application can establish a VPN.
         */
        val intent =
            VpnService.prepare(this)

        if (intent != null) {

            vpnPermissionLauncher.launch(
                intent
            )

        } else {

            /*
             * Permission was already granted.
             */
            startVpnService()
        }

        updateUi()
    }

    private fun disableAdBlocker() {

        preferences.setEnabled(false)

        stopVpnService()

        updateUi()
    }

    private fun startVpnService() {

        val intent =
            Intent(
                this,
                DnsVpnService::class.java
            )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            ContextCompat.startForegroundService(
                this,
                intent
            )

        } else {

            startService(intent)
        }
    }

    private fun stopVpnService() {

        val intent =
            Intent(
                this,
                DnsVpnService::class.java
            ).apply {

                action =
                    DnsVpnService.ACTION_STOP
            }

        startService(intent)
    }

    private fun updateUi() {

        val enabled =
            preferences.enabled.value

        val enableButton =
            findViewById<android.view.View>(
                R.id.enableButton
            )

        val disableButton =
            findViewById<android.view.View>(
                R.id.disableButton
            )

        enableButton.isEnabled =
            !enabled

        disableButton.isEnabled =
            enabled
    }

    override fun onResume() {
        super.onResume()

        /*
         * Refresh the UI when returning from the
         * Android VPN permission screen.
         */
        if (::preferences.isInitialized) {
            updateUi()
        }
    }
}

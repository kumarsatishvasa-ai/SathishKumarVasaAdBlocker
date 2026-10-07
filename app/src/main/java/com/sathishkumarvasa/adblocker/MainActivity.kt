package com.sathishkumarvasa.adblocker

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button
    private lateinit var blockedCountText: TextView
    private lateinit var ruleCountText: TextView
    private lateinit var updateButton: Button
    private lateinit var resetButton: Button

    private lateinit var preferences: AppPreferences
    private lateinit var repository: FilterRepository

    private val vpnPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->

            if (result.resultCode == RESULT_OK) {
                enableProtection()
            } else {
                Toast.makeText(
                    this,
                    "VPN permission was not granted.",
                    Toast.LENGTH_LONG
                ).show()

                preferences.setEnabled(false)
                updateUi()
            }
        }

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(savedInstanceState)

        setContentView(
            R.layout.activity_main
        )

        initializeDependencies()
        initializeViews()
        initializeListeners()

        updateUi()
    }

    private fun initializeDependencies() {

        preferences =
            AppPreferences(
                applicationContext
            )

        repository =
            FilterRepository(
                applicationContext,
                preferences
            )
    }

    private fun initializeViews() {

        statusText =
            findViewById(
                R.id.statusText
            )

        toggleButton =
            findViewById(
                R.id.toggleButton
            )

        blockedCountText =
            findViewById(
                R.id.blockedCountText
            )

        ruleCountText =
            findViewById(
                R.id.ruleCountText
            )

        updateButton =
            findViewById(
                R.id.updateButton
            )

        resetButton =
            findViewById(
                R.id.resetButton
            )
    }

    private fun initializeListeners() {

        toggleButton.setOnClickListener {

            if (
                preferences.enabled.value
            ) {
                disableProtection()
            } else {
                requestVpnPermission()
            }
        }

        updateButton.setOnClickListener {
            updateFilters()
        }

        resetButton.setOnClickListener {
            resetBlockedCounter()
        }
    }

    private fun requestVpnPermission() {

        val prepareIntent =
            VpnService.prepare(this)

        if (prepareIntent == null) {

            enableProtection()

        } else {

            vpnPermissionLauncher.launch(
                prepareIntent
            )
        }
    }

    private fun enableProtection() {

        preferences.setEnabled(true)

        val intent =
            Intent(
                this,
                DnsVpnService::class.java
            )

        try {

            ContextCompat.startForegroundService(
                this,
                intent
            )

            updateUi()

            Toast.makeText(
                this,
                "Protection enabled.",
                Toast.LENGTH_SHORT
            ).show()

        } catch (error: Exception) {

            preferences.setEnabled(false)

            updateUi()

            Toast.makeText(
                this,
                "Unable to start protection: ${
                    error.message ?: "Unknown error"
                }",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun disableProtection() {

        preferences.setEnabled(false)

        val intent =
            Intent(
                this,
                DnsVpnService::class.java
            ).apply {
                action =
                    DnsVpnService.ACTION_STOP
            }

        try {

            startService(intent)

        } catch (_: Exception) {
            /*
             * The service may already be stopped.
             */
        }

        updateUi()

        Toast.makeText(
            this,
            "Protection disabled.",
            Toast.LENGTH_SHORT
        ).show()
    }

    private fun updateFilters() {

        updateButton.isEnabled = false
        updateButton.text = "Updating..."

        lifecycleScope.launch {

            val result =
                withContext(
                    Dispatchers.IO
                ) {
                    try {
                        repository.updateFilters(
                            force = true
                        )
                    } catch (error: Exception) {

                        FilterUpdateResult(
                            success = false,
                            ruleCount =
                                preferences.ruleCount.value,
                            message =
                                error.message
                                    ?: "Filter update failed."
                        )
                    }
                }

            updateButton.isEnabled = true
            updateButton.text = "Update filters"

            if (result.success) {

                Toast.makeText(
                    this@MainActivity,
                    result.message,
                    Toast.LENGTH_SHORT
                ).show()

            } else {

                Toast.makeText(
                    this@MainActivity,
                    result.message,
                    Toast.LENGTH_LONG
                ).show()
            }

            updateUi()
        }
    }

    private fun resetBlockedCounter() {

        preferences.resetBlockedCount()

        updateUi()

        Toast.makeText(
            this,
            "Blocked counter reset.",
            Toast.LENGTH_SHORT
        ).show()
    }

    private fun updateUi() {

        val enabled =
            preferences.enabled.value

        if (enabled) {

            statusText.text =
                "PROTECTION ON"

            statusText.setTextColor(
                getColor(
                    android.R.color.holo_green_light
                )
            )

            toggleButton.text =
                "Turn protection OFF"

        } else {

            statusText.text =
                "PROTECTION OFF"

            statusText.setTextColor(
                getColor(
                    android.R.color.holo_red_light
                )
            )

            toggleButton.text =
                "Turn protection ON"
        }

        blockedCountText.text =
            preferences.blockedCount.value
                .toString()

        ruleCountText.text =
            preferences.ruleCount.value
                .toString()
    }

    override fun onResume() {
        super.onResume()

        updateUi()
    }
}

package com.sathishkumarvasa.adblocker

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var blockedCountText: TextView
    private lateinit var ruleCountText: TextView
    private lateinit var toggleButton: Button
    private lateinit var updateButton: Button
    private lateinit var resetButton: Button

    private val vpnPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->

            if (result.resultCode == Activity.RESULT_OK) {
                startAdBlocker()
            } else {
                updateStatus(false)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)

        initializeViews()
        setupButtons()
        refreshUi()

        startCounterRefresh()
    }

    private fun initializeViews() {

        statusText = findViewById(R.id.statusText)

        blockedCountText =
            findViewById(R.id.blockedCountText)

        ruleCountText =
            findViewById(R.id.ruleCountText)

        toggleButton =
            findViewById(R.id.toggleButton)

        updateButton =
            findViewById(R.id.updateButton)

        resetButton =
            findViewById(R.id.resetButton)
    }

    private fun setupButtons() {

        toggleButton.setOnClickListener {

            if (AdBlockVpnService.isRunning) {
                stopAdBlocker()
            } else {
                requestVpnPermission()
            }
        }

        updateButton.setOnClickListener {

            updateButton.isEnabled = false
            updateButton.text = "Updating..."

            lifecycleScope.launch {

                try {
                    FilterManager.updateFilters(this@MainActivity)
                } finally {

                    updateButton.isEnabled = true
                    updateButton.text = "Update filters"

                    refreshUi()
                }
            }
        }

        resetButton.setOnClickListener {

            AdBlockStorage.resetBlockedCount(this)

            refreshUi()
        }
    }

    private fun requestVpnPermission() {

        val intent =
            VpnService.prepare(this)

        if (intent != null) {

            vpnPermissionLauncher.launch(intent)

        } else {

            startAdBlocker()
        }
    }

    private fun startAdBlocker() {

        val intent =
            Intent(
                this,
                AdBlockVpnService::class.java
            )

        intent.action =
            AdBlockVpnService.ACTION_START

        startService(intent)

        updateStatus(true)
    }

    private fun stopAdBlocker() {

        val intent =
            Intent(
                this,
                AdBlockVpnService::class.java
            )

        intent.action =
            AdBlockVpnService.ACTION_STOP

        startService(intent)

        updateStatus(false)
    }

    private fun updateStatus(enabled: Boolean) {

        if (enabled) {

            statusText.text =
                "PROTECTION ON"

            statusText.setTextColor(
                getColor(
                    android.R.color.holo_green_dark
                )
            )

            toggleButton.text =
                "Turn protection OFF"

        } else {

            statusText.text =
                "PROTECTION OFF"

            statusText.setTextColor(
                getColor(
                    android.R.color.holo_red_dark
                )
            )

            toggleButton.text =
                "Turn protection ON"
        }
    }

    private fun refreshUi() {

        val running =
            AdBlockVpnService.isRunning

        updateStatus(running)

        val blocked =
            AdBlockStorage.getBlockedCount(
                this
            )

        blockedCountText.text =
            blocked.toString()

        val rules =
            AdBlockStorage.getRuleCount(
                this
            )

        ruleCountText.text =
            rules.toString()
    }

    private fun startCounterRefresh() {

        lifecycleScope.launch {

            while (true) {

                refreshUi()

                delay(1000)
            }
        }
    }

    override fun onResume() {
        super.onResume()

        refreshUi()
    }
}


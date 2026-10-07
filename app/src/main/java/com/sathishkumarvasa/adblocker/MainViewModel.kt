package com.sathishkumarvasa.adblocker

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MainViewModel(
    application: Application
) : AndroidViewModel(application) {

    private val preferences =
        AppPreferences(
            application.applicationContext
        )

    private val repository =
        FilterRepository(
            application.applicationContext,
            preferences
        )

    val enabled: StateFlow<Boolean> =
        preferences.enabled

    val blockedCount: StateFlow<Long> =
        preferences.blockedCount

    val ruleCount: StateFlow<Int> =
        preferences.ruleCount

    val lastUpdate: StateFlow<Long> =
        preferences.lastUpdate

    val allowlist: StateFlow<List<String>> =
        preferences.allowlist

    val customRules: StateFlow<List<String>> =
        preferences.customRules

    private var updateInProgress = false

    fun setEnabled(
        enabled: Boolean
    ) {
        preferences.setEnabled(enabled)
    }

    fun toggleProtection() {
        setEnabled(
            !preferences.enabled.value
        )
    }

    fun resetBlockedCount() {
        preferences.resetBlockedCount()
    }

    fun updateFilters() {

        if (updateInProgress) {
            return
        }

        updateInProgress = true

        viewModelScope.launch {

            try {

                repository.updateFilters(
                    force = true
                )

            } finally {

                updateInProgress = false
            }
        }
    }

    fun addAllowlistDomain(
        domain: String
    ): Boolean {

        return preferences.addAllowlistDomain(
            domain
        )
    }

    fun removeAllowlistDomain(
        domain: String
    ): Boolean {

        return preferences.removeAllowlistDomain(
            domain
        )
    }

    fun isAllowlisted(
        domain: String
    ): Boolean {

        return preferences.isAllowlisted(
            domain
        )
    }

    fun addCustomRule(
        rule: String
    ): Boolean {

        return preferences.addCustomRule(
            rule
        )
    }

    fun removeCustomRule(
        rule: String
    ): Boolean {

        return preferences.removeCustomRule(
            rule
        )
    }

    fun clearAllCustomRules() {
        preferences.clearAllCustomRules()
    }

    suspend fun updateFiltersNow():
        FilterUpdateResult {

        return repository.updateFilters(
            force = true
        )
    }

    fun refreshRuleCount() {

        viewModelScope.launch {

            val rules =
                repository.loadRules()

            preferences.setRuleCount(
                rules.size
            )
        }
    }
}


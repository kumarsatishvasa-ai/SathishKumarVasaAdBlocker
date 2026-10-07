package com.sathishkumarvasa.adblocker

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class AppPreferences(
    context: Context
) {

    private val preferences =
        context.getSharedPreferences(
            "adblocker_preferences",
            Context.MODE_PRIVATE
        )

    private val enabledState =
        MutableStateFlow(
            preferences.getBoolean(
                KEY_ENABLED,
                true
            )
        )

    private val blockedCountState =
        MutableStateFlow(
            preferences.getLong(
                KEY_BLOCKED_COUNT,
                0L
            )
        )

    private val ruleCountState =
        MutableStateFlow(
            preferences.getInt(
                KEY_RULE_COUNT,
                0
            )
        )

    private val lastUpdateState =
        MutableStateFlow(
            preferences.getLong(
                KEY_LAST_UPDATE,
                0L
            )
        )

    private val allowlistState =
        MutableStateFlow(
            preferences
                .getStringSet(
                    KEY_ALLOWLIST,
                    emptySet()
                )
                ?.toList()
                ?: emptyList()
        )

    private val customRulesState =
        MutableStateFlow(
            preferences
                .getStringSet(
                    KEY_CUSTOM_RULES,
                    emptySet()
                )
                ?.toList()
                ?: emptyList()
        )

    val enabled: StateFlow<Boolean> =
        enabledState

    val blockedCount: StateFlow<Long> =
        blockedCountState

    val ruleCount: StateFlow<Int> =
        ruleCountState

    val lastUpdate: StateFlow<Long> =
        lastUpdateState

    val allowlist: StateFlow<List<String>> =
        allowlistState

    val customRules: StateFlow<List<String>> =
        customRulesState

    fun setEnabled(value: Boolean) {

        preferences
            .edit()
            .putBoolean(
                KEY_ENABLED,
                value
            )
            .apply()

        enabledState.value = value
    }

    fun setBlockedCount(value: Long) {

        val safeValue =
            value.coerceAtLeast(0L)

        preferences
            .edit()
            .putLong(
                KEY_BLOCKED_COUNT,
                safeValue
            )
            .apply()

        blockedCountState.value =
            safeValue
    }

    fun incrementBlockedCount(
        amount: Long = 1L
    ) {

        if (amount <= 0L) {
            return
        }

        val newValue =
            blockedCountState.value + amount

        setBlockedCount(newValue)
    }

    fun resetBlockedCount() {
        setBlockedCount(0L)
    }

    fun setRuleCount(value: Int) {

        val safeValue =
            value.coerceAtLeast(0)

        preferences
            .edit()
            .putInt(
                KEY_RULE_COUNT,
                safeValue
            )
            .apply()

        ruleCountState.value =
            safeValue
    }

    fun setLastUpdate(timestamp: Long) {

        preferences
            .edit()
            .putLong(
                KEY_LAST_UPDATE,
                timestamp
            )
            .apply()

        lastUpdateState.value =
            timestamp
    }

    fun addAllowlistDomain(
        domain: String
    ): Boolean {

        val normalized =
            normalizeDomain(domain)

        if (normalized.isEmpty()) {
            return false
        }

        val current =
            allowlistState.value
                .toMutableSet()

        if (!current.add(normalized)) {
            return false
        }

        saveAllowlist(current)

        return true
    }

    fun removeAllowlistDomain(
        domain: String
    ): Boolean {

        val normalized =
            normalizeDomain(domain)

        val current =
            allowlistState.value
                .toMutableSet()

        if (!current.remove(normalized)) {
            return false
        }

        saveAllowlist(current)

        return true
    }

    fun isAllowlisted(
        domain: String
    ): Boolean {

        val normalized =
            normalizeDomain(domain)

        if (normalized.isEmpty()) {
            return false
        }

        return allowlistState.value.any {
            it == normalized ||
                normalized.endsWith(
                    ".$it"
                )
        }
    }

    private fun saveAllowlist(
        domains: Set<String>
    ) {

        val sorted =
            domains
                .filter {
                    it.isNotBlank()
                }
                .map {
                    normalizeDomain(it)
                }
                .filter {
                    it.isNotEmpty()
                }
                .distinct()
                .sorted()

        preferences
            .edit()
            .putStringSet(
                KEY_ALLOWLIST,
                sorted.toSet()
            )
            .apply()

        allowlistState.value =
            sorted
    }

    fun addCustomRule(
        rule: String
    ): Boolean {

        val value =
            rule.trim()

        if (value.isEmpty()) {
            return false
        }

        val current =
            customRulesState.value
                .toMutableSet()

        if (!current.add(value)) {
            return false
        }

        saveCustomRules(current)

        return true
    }

    fun removeCustomRule(
        rule: String
    ): Boolean {

        val current =
            customRulesState.value
                .toMutableSet()

        if (!current.remove(rule)) {
            return false
        }

        saveCustomRules(current)

        return true
    }

    private fun saveCustomRules(
        rules: Set<String>
    ) {

        val sorted =
            rules
                .filter {
                    it.isNotBlank()
                }
                .map {
                    it.trim()
                }
                .distinct()
                .sorted()

        preferences
            .edit()
            .putStringSet(
                KEY_CUSTOM_RULES,
                sorted.toSet()
            )
            .apply()

        customRulesState.value =
            sorted
    }

    fun clearAllCustomRules() {

        preferences
            .edit()
            .remove(KEY_CUSTOM_RULES)
            .apply()

        customRulesState.value =
            emptyList()
    }

    private fun normalizeDomain(
        domain: String
    ): String {

        var value =
            domain
                .trim()
                .lowercase()

        if (
            value.startsWith("https://")
        ) {
            value =
                value.removePrefix(
                    "https://"
                )
        }

        if (
            value.startsWith("http://")
        ) {
            value =
                value.removePrefix(
                    "http://"
                )
        }

        value =
            value.substringBefore("/")

        value =
            value.substringBefore("?")

        value =
            value.substringBefore("#")

        value =
            value.substringBefore(":")

        value =
            value
                .trim('.')

        return value
    }

    companion object {

        private const val KEY_ENABLED =
            "enabled"

        private const val KEY_BLOCKED_COUNT =
            "blocked_count"

        private const val KEY_RULE_COUNT =
            "rule_count"

        private const val KEY_LAST_UPDATE =
            "last_update"

        private const val KEY_ALLOWLIST =
            "allowlist"

        private const val KEY_CUSTOM_RULES =
            "custom_rules"
    }
}


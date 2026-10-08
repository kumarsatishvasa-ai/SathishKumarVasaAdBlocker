package com.sathishkumarvasa.adblocker

import android.content.Context

object AdBlockStorage {

    private const val PREFS = "adblock_storage"

    private const val KEY_ENABLED = "enabled"
    private const val KEY_BLOCKED_COUNT = "blocked_count"
    private const val KEY_RULE_COUNT = "rule_count"
    private const val KEY_LAST_UPDATE = "last_update"
    private const val KEY_ALLOWLIST = "allowlist"
    private const val KEY_CUSTOM_RULES = "custom_rules"

    private fun prefs(context: Context) =
        context.getSharedPreferences(
            PREFS,
            Context.MODE_PRIVATE
        )

    fun isEnabled(context: Context): Boolean {
        return prefs(context).getBoolean(
            KEY_ENABLED,
            true
        )
    }

    fun setEnabled(
        context: Context,
        enabled: Boolean
    ) {
        prefs(context)
            .edit()
            .putBoolean(
                KEY_ENABLED,
                enabled
            )
            .apply()
    }

    fun incrementBlockedCount(
        context: Context
    ) {
        val current =
            getBlockedCount(context)

        prefs(context)
            .edit()
            .putLong(
                KEY_BLOCKED_COUNT,
                current + 1
            )
            .apply()
    }

    fun getBlockedCount(
        context: Context
    ): Long {
        return prefs(context).getLong(
            KEY_BLOCKED_COUNT,
            0L
        )
    }

    fun resetBlockedCount(
        context: Context
    ) {
        prefs(context)
            .edit()
            .putLong(
                KEY_BLOCKED_COUNT,
                0L
            )
            .apply()
    }

    fun setRuleCount(
        context: Context,
        count: Int
    ) {
        prefs(context)
            .edit()
            .putInt(
                KEY_RULE_COUNT,
                count
            )
            .apply()
    }

    fun getRuleCount(
        context: Context
    ): Int {
        return prefs(context).getInt(
            KEY_RULE_COUNT,
            0
        )
    }

    fun setLastUpdate(
        context: Context
    ) {
        prefs(context)
            .edit()
            .putLong(
                KEY_LAST_UPDATE,
                System.currentTimeMillis()
            )
            .apply()
    }

    fun getLastUpdate(
        context: Context
    ): Long {
        return prefs(context).getLong(
            KEY_LAST_UPDATE,
            0L
        )
    }

    fun getAllowlist(
        context: Context
    ): Set<String> {
        return prefs(context)
            .getStringSet(
                KEY_ALLOWLIST,
                emptySet()
            )
            ?.map {
                it.trim()
                    .trim('.')
                    .lowercase()
            }
            ?.toSet()
            ?: emptySet()
    }

    fun setAllowlist(
        context: Context,
        hosts: Set<String>
    ) {
        val normalized =
            hosts
                .map {
                    it.trim()
                        .trim('.')
                        .lowercase()
                }
                .filter {
                    it.isNotEmpty()
                }
                .toSet()

        prefs(context)
            .edit()
            .putStringSet(
                KEY_ALLOWLIST,
                normalized
            )
            .apply()
    }

    fun addAllowlistHost(
        context: Context,
        host: String
    ) {
        val current =
            getAllowlist(context)
                .toMutableSet()

        current.add(
            host.trim()
                .trim('.')
                .lowercase()
        )

        setAllowlist(
            context,
            current
        )
    }

    fun removeAllowlistHost(
        context: Context,
        host: String
    ) {
        val current =
            getAllowlist(context)
                .toMutableSet()

        current.remove(
            host.trim()
                .trim('.')
                .lowercase()
        )

        setAllowlist(
            context,
            current
        )
    }

    fun getCustomRules(
        context: Context
    ): Set<String> {
        return prefs(context)
            .getStringSet(
                KEY_CUSTOM_RULES,
                emptySet()
            )
            ?.toSet()
            ?: emptySet()
    }

    fun setCustomRules(
        context: Context,
        rules: Set<String>
    ) {
        prefs(context)
            .edit()
            .putStringSet(
                KEY_CUSTOM_RULES,
                rules
            )
            .apply()
    }

    fun addCustomRule(
        context: Context,
        rule: String
    ) {
        val current =
            getCustomRules(context)
                .toMutableSet()

        if (rule.isNotBlank()) {
            current.add(rule.trim())
        }

        setCustomRules(
            context,
            current
        )
    }

    fun clearAll(
        context: Context
    ) {
        prefs(context)
            .edit()
            .clear()
            .apply()
    }
}

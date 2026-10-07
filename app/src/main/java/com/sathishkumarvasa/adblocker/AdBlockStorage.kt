package com.sathishkumarvasa.adblocker

import android.content.Context

object AdBlockStorage {

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker"

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


    private fun preferences(context: Context) =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )


    // ---------------------------------------------------
    // Protection enabled
    // ---------------------------------------------------

    fun isEnabled(context: Context): Boolean {

        return preferences(context)
            .getBoolean(
                KEY_ENABLED,
                true
            )
    }


    fun setEnabled(
        context: Context,
        enabled: Boolean
    ) {

        preferences(context)
            .edit()
            .putBoolean(
                KEY_ENABLED,
                enabled
            )
            .apply()
    }


    // ---------------------------------------------------
    // Blocked counter
    // ---------------------------------------------------

    fun getBlockedCount(
        context: Context
    ): Long {

        return preferences(context)
            .getLong(
                KEY_BLOCKED_COUNT,
                0L
            )
    }


    fun setBlockedCount(
        context: Context,
        count: Long
    ) {

        preferences(context)
            .edit()
            .putLong(
                KEY_BLOCKED_COUNT,
                count.coerceAtLeast(0L)
            )
            .apply()
    }


    fun incrementBlockedCount(
        context: Context,
        amount: Long = 1L
    ) {

        if (amount <= 0L) {
            return
        }

        synchronized(this) {

            val current =
                getBlockedCount(context)

            setBlockedCount(
                context,
                current + amount
            )
        }
    }


    fun resetBlockedCount(
        context: Context
    ) {

        setBlockedCount(
            context,
            0L
        )
    }


    // ---------------------------------------------------
    // Filter rule count
    // ---------------------------------------------------

    fun getRuleCount(
        context: Context
    ): Int {

        return preferences(context)
            .getInt(
                KEY_RULE_COUNT,
                0
            )
    }


    fun setRuleCount(
        context: Context,
        count: Int
    ) {

        preferences(context)
            .edit()
            .putInt(
                KEY_RULE_COUNT,
                count.coerceAtLeast(0)
            )
            .apply()
    }


    // ---------------------------------------------------
    // Last filter update
    // ---------------------------------------------------

    fun getLastUpdate(
        context: Context
    ): Long {

        return preferences(context)
            .getLong(
                KEY_LAST_UPDATE,
                0L
            )
    }


    fun setLastUpdate(
        context: Context,
        timestamp: Long = System.currentTimeMillis()
    ) {

        preferences(context)
            .edit()
            .putLong(
                KEY_LAST_UPDATE,
                timestamp
            )
            .apply()
    }


    // ---------------------------------------------------
    // Allowlist
    // ---------------------------------------------------

    fun getAllowlist(
        context: Context
    ): Set<String> {

        return preferences(context)
            .getStringSet(
                KEY_ALLOWLIST,
                emptySet()
            )
            ?.toSet()
            ?: emptySet()
    }


    fun setAllowlist(
        context: Context,
        domains: Collection<String>
    ) {

        val cleaned =
            domains
                .map {
                    it.trim()
                        .lowercase()
                }
                .filter {
                    it.isNotEmpty()
                }
                .toSet()

        preferences(context)
            .edit()
            .putStringSet(
                KEY_ALLOWLIST,
                cleaned
            )
            .apply()
    }


    fun addAllowlistedDomain(
        context: Context,
        domain: String
    ) {

        val cleaned =
            domain
                .trim()
                .lowercase()

        if (cleaned.isEmpty()) {
            return
        }

        val domains =
            getAllowlist(context)
                .toMutableSet()

        domains.add(cleaned)

        setAllowlist(
            context,
            domains
        )
    }


    fun removeAllowlistedDomain(
        context: Context,
        domain: String
    ) {

        val cleaned =
            domain
                .trim()
                .lowercase()

        val domains =
            getAllowlist(context)
                .toMutableSet()

        domains.remove(cleaned)

        setAllowlist(
            context,
            domains
        )
    }


    fun isDomainAllowlisted(
        context: Context,
        domain: String
    ): Boolean {

        val cleaned =
            domain
                .trim()
                .lowercase()

        return getAllowlist(context)
            .contains(cleaned)
    }


    // ---------------------------------------------------
    // Custom rules
    // ---------------------------------------------------

    fun getCustomRules(
        context: Context
    ): List<String> {

        return preferences(context)
            .getStringSet(
                KEY_CUSTOM_RULES,
                emptySet()
            )
            ?.toList()
            ?: emptyList()
    }


    fun setCustomRules(
        context: Context,
        rules: Collection<String>
    ) {

        val cleaned =
            rules
                .map {
                    it.trim()
                }
                .filter {
                    it.isNotEmpty()
                }
                .toSet()

        preferences(context)
            .edit()
            .putStringSet(
                KEY_CUSTOM_RULES,
                cleaned
            )
            .apply()
    }


    fun addCustomRule(
        context: Context,
        rule: String
    ): Boolean {

        val cleaned =
            rule.trim()

        if (cleaned.isEmpty()) {
            return false
        }

        val rules =
            getCustomRules(context)
                .toMutableSet()

        val added =
            rules.add(cleaned)

        if (added) {

            setCustomRules(
                context,
                rules
            )
        }

        return added
    }


    fun removeCustomRule(
        context: Context,
        rule: String
    ) {

        val rules =
            getCustomRules(context)
                .toMutableSet()

        rules.remove(
            rule.trim()
        )

        setCustomRules(
            context,
            rules
        )
    }


    // ---------------------------------------------------
    // Reset application data
    // ---------------------------------------------------

    fun resetAll(
        context: Context
    ) {

        preferences(context)
            .edit()
            .clear()
            .apply()

        // Protection is enabled by default.
        setEnabled(
            context,
            true
        )
    }
}

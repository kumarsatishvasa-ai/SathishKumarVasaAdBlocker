package com.sathishkumarvasa.adblocker

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.util.Locale

object FilterManager {

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    private const val MAX_HOSTS =
        100_000

    /*
     * These lists contain browser ad-blocking rules.
     *
     * We extract only rules that can safely be converted
     * into DNS hostnames.
     */
    private val FILTER_LISTS =
        listOf(
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt"
        )

    // ============================================================
    // UPDATE FILTERS
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val hosts =
                LinkedHashSet<String>()

            var successfulDownloads = 0

            /*
             * Download each filter list.
             */
            for (url in FILTER_LISTS) {

                if (
                    hosts.size >= MAX_HOSTS
                ) {
                    break
                }

                val text =
                    downloadFilterList(url)

                if (text.isBlank()) {
                    continue
                }

                successfulDownloads++

                val parsedHosts =
                    parseFilterList(text)

                for (host in parsedHosts) {

                    if (
                        hosts.size >= MAX_HOSTS
                    ) {
                        break
                    }

                    if (
                        !isAllowlisted(
                            context,
                            host
                        )
                    ) {
                        hosts.add(host)
                    }
                }
            }

            /*
             * Add custom rules saved by the application.
             */
            val customRules =
                try {
                    AdBlockStorage.getCustomRules(
                        context
                    )
                } catch (_: Exception) {
                    emptySet<String>()
                }

            for (rule in customRules) {

                if (
                    hosts.size >= MAX_HOSTS
                ) {
                    break
                }

                val host =
                    extractHostFromRule(rule)

                if (
                    host != null &&
                    isValidHost(host) &&
                    !isAllowlisted(
                        context,
                        host
                    )
                ) {
                    hosts.add(host)
                }
            }

            /*
             * Never replace an existing working database
             * with an empty database because the Internet
             * was temporarily unavailable.
             */
            if (
                successfulDownloads == 0 &&
                hosts.isEmpty()
            ) {

                android.util.Log.w(
                    "FilterManager",
                    "No filter lists downloaded; keeping existing database"
                )

                return@withContext false
            }

            /*
             * Save the new database.
             */
            saveBlockedHosts(
                context,
                hosts
            )

            try {

                AdBlockStorage.setRuleCount(
                    context,
                    hosts.size
                )

                AdBlockStorage.setLastUpdate(
                    context
                )

            } catch (_: Exception) {
            }

            preferences(context)
                .edit()
                .putLong(
                    KEY_LAST_UPDATE,
                    System.currentTimeMillis()
                )
                .apply()

            android.util.Log.i(
                "FilterManager",
                "Loaded ${hosts.size} DNS host rules"
            )

            true

        } catch (e: Exception) {

            android.util.Log.e(
                "FilterManager",
                "Filter update failed",
                e
            )

            false
        }
    }

    // ============================================================
    // DOWNLOAD
    // ============================================================

    private fun downloadFilterList(
        url: String
    ): String {

        var connection:
            HttpURLConnection? = null

        return try {

            connection =
                (
                    URI(url)
                        .toURL()
                        .openConnection()
                        as HttpURLConnection
                    )

            connection.connectTimeout =
                15_000

            connection.readTimeout =
                30_000

            connection.requestMethod =
                "GET"

            connection.instanceFollowRedirects =
                true

            connection.setRequestProperty(
                "User-Agent",
                "SathishKumarVasaAdBlocker/1.0"
            )

            connection.setRequestProperty(
                "Accept",
                "text/plain,text/*,*/*"
            )

            val responseCode =
                connection.responseCode

            if (
                responseCode !in 200..299
            ) {

                android.util.Log.w(
                    "FilterManager",
                    "HTTP $responseCode from $url"
                )

                return ""
            }

            connection.inputStream
                .bufferedReader()
                .use {
                    it.readText()
                }

        } catch (e: Exception) {

            android.util.Log.w(
                "FilterManager",
                "Could not download $url",
                e
            )

            ""

        } finally {

            try {
                connection?.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    // ============================================================
    // PARSE FILTER LIST
    // ============================================================

    private fun parseFilterList(
        text: String
    ): Set<String> {

        val hosts =
            LinkedHashSet<String>()

        val lines =
            text.split(
                Regex("\\r?\\n")
            )

        for (rawLine in lines) {

            if (
                hosts.size >= MAX_HOSTS
            ) {
                break
            }

            var line =
                rawLine.trim()

            if (line.isEmpty()) {
                continue
            }

            /*
             * Comments.
             */
            if (
                line.startsWith("!")
            ) {
                continue
            }

            /*
             * Metadata.
             */
            if (
                line.startsWith("[")
            ) {
                continue
            }

            /*
             * Exception rules.
             *
             * A simple DNS filter cannot reproduce
             * the full meaning of an ABP exception rule.
             */
            if (
                line.startsWith("@@")
            ) {
                continue
            }

            /*
             * Cosmetic/browser rules are not DNS rules.
             */
            if (
                line.contains("##") ||
                line.contains("#@#") ||
                line.contains("#?#") ||
                line.contains("#@?#") ||
                line.contains("#$#") ||
                line.contains("#@$#")
            ) {
                continue
            }

            /*
             * Remove ABP options.
             *
             * Example:
             *
             * ||ads.example.com^$script,image
             */
            val dollarIndex =
                line.indexOf('$')

            if (
                dollarIndex >= 0
            ) {

                line =
                    line.substring(
                        0,
                        dollarIndex
                    )
            }

            line =
                line.trim()

            if (line.isEmpty()) {
                continue
            }

            val host =
                extractHostFromRule(line)

            if (
                host != null &&
                isValidHost(host)
            ) {
                hosts.add(host)
            }
        }

        return hosts
    }

    // ============================================================
    // EXTRACT HOSTNAME
    // ============================================================

    private fun extractHostFromRule(
        rule: String
    ): String? {

        var value =
            rule.trim()

        if (value.isEmpty()) {
            return null
        }

        /*
         * ABP domain anchor.
         *
         * ||ads.example.com^
         */
        if (
            value.startsWith("||")
        ) {
            value =
                value.substring(2)
        }

        /*
         * Hosts-file rules.
         *
         * 0.0.0.0 ads.example.com
         * 127.0.0.1 ads.example.com
         */
        val parts =
            value.split(
                Regex("\\s+")
            )

        if (
            parts.size >= 2 &&
            (
                parts[0] == "0.0.0.0" ||
                parts[0] == "127.0.0.1" ||
                parts[0] == "::" ||
                parts[0] == "::1"
            )
        ) {

            value =
                parts[1]
        }

        /*
         * Remove URL schemes.
         */
        value =
            value.removePrefix(
                "http://"
            )

        value =
            value.removePrefix(
                "https://"
            )

        /*
         * Remove leading wildcard.
         */
        if (
            value.startsWith("|")
        ) {
            value =
                value.removePrefix("|")
        }

        /*
         * Remove www.
         */
        value =
            value.removePrefix(
                "www."
            )

        /*
         * ABP separator.
         */
        val separatorIndex =
            value.indexOf('^')

        if (
            separatorIndex >= 0
        ) {

            value =
                value.substring(
                    0,
                    separatorIndex
                )
        }

        /*
         * Remove path.
         */
        val slashIndex =
            value.indexOf('/')

        if (
            slashIndex >= 0
        ) {

            value =
                value.substring(
                    0,
                    slashIndex
                )
        }

        /*
         * Remove query.
         */
        val questionIndex =
            value.indexOf('?')

        if (
            questionIndex >= 0
        ) {

            value =
                value.substring(
                    0,
                    questionIndex
                )
        }

        /*
         * Remove fragment.
         */
        val fragmentIndex =
            value.indexOf('#')

        if (
            fragmentIndex >= 0
        ) {

            value =
                value.substring(
                    0,
                    fragmentIndex
                )
        }

        /*
         * DNS cannot represent wildcard rules.
         */
        if (
            value.contains("*") ||
            value.contains("%") ||
            value.contains("|")
        ) {
            return null
        }

        /*
         * Remove port.
         */
        val colonIndex =
            value.indexOf(':')

        if (
            colonIndex >= 0
        ) {

            value =
                value.substring(
                    0,
                    colonIndex
                )
        }

        value =
            value.trim()
                .trim('.')
                .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Reject obviously non-host values.
         */
        if (
            value.contains("=") ||
            value.contains("&") ||
            value.contains(" ") ||
            value.contains(",")
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // VALID HOSTNAME
    // ============================================================

    private fun isValidHost(
        host: String
    ): Boolean {

        if (
            host.length < 3 ||
            host.length > 253
        ) {
            return false
        }

        if (
            host.startsWith(".") ||
            host.endsWith(".")
        ) {
            return false
        }

        if (
            host.contains("..")
        ) {
            return false
        }

        /*
         * Do not block local names.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        /*
         * Do not store IPv4 addresses as host rules.
         */
        if (
            isIpv4Address(host)
        ) {
            return false
        }

        val labels =
            host.split(".")

        /*
         * A DNS filtering rule should normally
         * contain at least a domain and TLD.
         */
        if (
            labels.size < 2
        ) {
            return false
        }

        for (label in labels) {

            if (
                label.isEmpty() ||
                label.length > 63
            ) {
                return false
            }

            if (
                label.startsWith("-") ||
                label.endsWith("-")
            ) {
                return false
            }

            for (character in label) {

                val valid =
                    character.isLetterOrDigit() ||
                        character == '-'

                if (!valid) {
                    return false
                }
            }
        }

        return true
    }

    // ============================================================
    // IPV4 CHECK
    // ============================================================

    private fun isIpv4Address(
        value: String
    ): Boolean {

        val parts =
            value.split(".")

        if (
            parts.size != 4
        ) {
            return false
        }

        for (part in parts) {

            if (part.isEmpty()) {
                return false
            }

            val number =
                part.toIntOrNull()
                    ?: return false

            if (
                number !in 0..255
            ) {
                return false
            }
        }

        return true
    }

    // ============================================================
    // ALLOWLIST
    // ============================================================

    private fun isAllowlisted(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (normalized.isEmpty()) {
            return false
        }

        val allowlist =
            try {

                AdBlockStorage.getAllowlist(
                    context
                )

            } catch (_: Exception) {

                emptySet()
            }

        val normalizedAllowlist =
            allowlist
                .map {
                    it.trim()
                        .trim('.')
                        .lowercase(Locale.US)
                }
                .toSet()

        if (
            normalizedAllowlist.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain matching.
         *
         * Allow:
         * example.com
         *
         * Also allows:
         * ads.example.com
         */
        var current =
            normalized

        while (true) {

            val dot =
                current.indexOf('.')

            if (dot < 0) {
                break
            }

            current =
                current.substring(
                    dot + 1
                )

            if (
                normalizedAllowlist.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // STORAGE
    // ============================================================

    private fun preferences(
        context: Context
    ) =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    private fun saveBlockedHosts(
        context: Context,
        hosts: Set<String>
    ) {

        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                hosts
            )
            .apply()
    }

    // ============================================================
    // GET BLOCKED HOSTS
    // ============================================================

    fun getBlockedHosts(
        context: Context
    ): Set<String> {

        return preferences(context)
            .getStringSet(
                KEY_BLOCKED_HOSTS,
                emptySet()
            )
            ?.toSet()
            ?: emptySet()
    }

    // ============================================================
    // CHECK HOST
    // ============================================================

    fun isBlockedHost(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (normalized.isEmpty()) {
            return false
        }

        /*
         * Allowlist has priority.
         */
        if (
            isAllowlisted(
                context,
                normalized
            )
        ) {
            return false
        }

        val blockedHosts =
            getBlockedHosts(context)

        /*
         * Exact match.
         */
        if (
            blockedHosts.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain match.
         *
         * Example:
         *
         * query:
         * ads.tracker.example.com
         *
         * database:
         * example.com
         *
         * => blocked
         */
        var current =
            normalized

        while (true) {

            val dot =
                current.indexOf('.')

            if (dot < 0) {
                break
            }

            current =
                current.substring(
                    dot + 1
                )

            if (
                blockedHosts.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // CLEAR FILTERS
    // ============================================================

    fun clearFilters(
        context: Context
    ) {

        preferences(context)
            .edit()
            .remove(
                KEY_BLOCKED_HOSTS
            )
            .remove(
                KEY_LAST_UPDATE
            )
            .apply()

        try {

            AdBlockStorage.setRuleCount(
                context,
                0
            )

        } catch (_: Exception) {
        }
    }

    // ============================================================
    // LAST UPDATE
    // ============================================================

    fun getLastUpdate(
        context: Context
    ): Long {

        return preferences(context)
            .getLong(
                KEY_LAST_UPDATE,
                0L
            )
    }
}

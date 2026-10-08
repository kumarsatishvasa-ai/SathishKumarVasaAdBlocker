package com.sathishkumarvasa.adblocker

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.util.Locale

object FilterManager {

    private const val TAG = "FilterManager"

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    /*
     * Keep the DNS database conservative.
     *
     * A browser filter list can contain thousands of rules
     * that cannot safely be converted into DNS hostname rules.
     */
    private const val MAX_HOSTS = 100_000

    /*
     * We intentionally use the hostname-capable lists only.
     */
    private val FILTER_LISTS = listOf(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
    )

    /*
     * Domains that must NEVER be blocked by this DNS filter.
     *
     * YouTube and Google use many different hostnames, so
     * these are handled as parent domains.
     */
    private val ALWAYS_ALLOWED_DOMAINS = setOf(
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googlevideo.com",
        "youtube.com",
        "youtube-nocookie.com",
        "ytimg.com",
        "youtu.be",
        "ggpht.com",
        "android.com",
        "android.clients.google.com",
        "play.google.com",
        "accounts.google.com",
        "accounts.youtube.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com"
    )

    // ============================================================
    // UPDATE FILTERS
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        try {
            val hosts = LinkedHashSet<String>()

            var successfulDownloads = 0

            for (url in FILTER_LISTS) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                val text = downloadFilterList(url)

                if (text.isBlank()) {
                    continue
                }

                successfulDownloads++

                val parsedHosts = parseFilterList(text)

                for (host in parsedHosts) {

                    if (hosts.size >= MAX_HOSTS) {
                        break
                    }

                    if (!isAlwaysAllowed(host) &&
                        !isAllowlisted(context, host)
                    ) {
                        hosts.add(host)
                    }
                }
            }

            /*
             * Add custom rules.
             */
            val customRules =
                try {
                    AdBlockStorage.getCustomRules(context)
                } catch (_: Exception) {
                    emptySet<String>()
                }

            for (rule in customRules) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                val host = extractHostFromRule(rule)

                if (
                    host != null &&
                    isValidHost(host) &&
                    !isAlwaysAllowed(host) &&
                    !isAllowlisted(context, host)
                ) {
                    hosts.add(host)
                }
            }

            /*
             * Never replace a working database with nothing.
             */
            if (
                successfulDownloads == 0 &&
                hosts.isEmpty()
            ) {
                Log.w(
                    TAG,
                    "No filter lists downloaded; keeping existing database"
                )

                return@withContext false
            }

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

            Log.i(
                TAG,
                "Loaded ${hosts.size} safe DNS host rules"
            )

            true

        } catch (e: Exception) {

            Log.e(
                TAG,
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

        var connection: HttpURLConnection? = null

        return try {

            connection =
                URI(url)
                    .toURL()
                    .openConnection() as HttpURLConnection

            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true

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

            if (responseCode !in 200..299) {

                Log.w(
                    TAG,
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

            Log.w(
                TAG,
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

        val hosts = LinkedHashSet<String>()

        val lines =
            text.split(
                Regex("\\r?\\n")
            )

        for (rawLine in lines) {

            if (hosts.size >= MAX_HOSTS) {
                break
            }

            val line = rawLine.trim()

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
             * DNS filtering cannot safely reproduce
             * browser exception semantics.
             */
            if (
                line.startsWith("@@")
            ) {
                continue
            }

            /*
             * Cosmetic rules are not DNS rules.
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
             * IMPORTANT:
             *
             * Only accept explicit domain-anchored ABP rules:
             *
             * ||ads.example.com^
             *
             * This prevents arbitrary URL/path/browser rules
             * from being interpreted as DNS hostnames.
             */
            if (!line.startsWith("||")) {
                continue
            }

            /*
             * Remove options.
             */
            val dollarIndex =
                line.indexOf('$')

            val cleanRule =
                if (dollarIndex >= 0) {
                    line.substring(
                        0,
                        dollarIndex
                    )
                } else {
                    line
                }

            val host =
                extractHostFromRule(
                    cleanRule
                )

            if (
                host != null &&
                isSafeFilterHost(host) &&
                !isAlwaysAllowed(host)
            ) {
                hosts.add(host)
            }
        }

        return hosts
    }

    // ============================================================
    // EXTRACT HOST
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
         * ABP:
         *
         * ||ads.example.com^
         */
        if (
            value.startsWith("||")
        ) {
            value = value.substring(2)
        }

        /*
         * Hosts-file format.
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
            value = parts[1]
        }

        /*
         * Remove URL scheme.
         */
        value = value.removePrefix("http://")
        value = value.removePrefix("https://")

        /*
         * Remove leading separator.
         */
        if (value.startsWith("|")) {
            value = value.removePrefix("|")
        }

        /*
         * ABP separator.
         */
        val separatorIndex =
            value.indexOf('^')

        if (separatorIndex >= 0) {
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

        if (slashIndex >= 0) {
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

        if (questionIndex >= 0) {
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

        if (fragmentIndex >= 0) {
            value =
                value.substring(
                    0,
                    fragmentIndex
                )
        }

        /*
         * DNS hostnames cannot contain wildcards.
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

        if (colonIndex >= 0) {
            value =
                value.substring(
                    0,
                    colonIndex
                )
        }

        value =
            value
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Reject non-host values.
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
    // SAFE FILTER HOST
    // ============================================================

    private fun isSafeFilterHost(
        host: String
    ): Boolean {

        if (!isValidHost(host)) {
            return false
        }

        /*
         * Never allow critical services into the
         * blocked database.
         */
        if (isAlwaysAllowed(host)) {
            return false
        }

        /*
         * Reject very broad public domains.
         *
         * A DNS ad blocker should never receive a rule
         * such as:
         *
         * com
         * net
         * org
         *
         * isValidHost already rejects those, but this
         * additional protection is intentional.
         */
        val labels =
            host.split(".")

        if (labels.size < 2) {
            return false
        }

        /*
         * A two-label domain is allowed only when it
         * is explicitly present in a ||domain^ rule.
         *
         * parseFilterList already guarantees this.
         */
        return true
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

        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        if (
            isIpv4Address(host)
        ) {
            return false
        }

        val labels =
            host.split(".")

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
    // IPV4
    // ============================================================

    private fun isIpv4Address(
        value: String
    ): Boolean {

        val parts =
            value.split(".")

        if (parts.size != 4) {
            return false
        }

        for (part in parts) {

            if (part.isEmpty()) {
                return false
            }

            val number =
                part.toIntOrNull()
                    ?: return false

            if (number !in 0..255) {
                return false
            }
        }

        return true
    }

    // ============================================================
    // ALWAYS ALLOWED
    // ============================================================

    private fun isAlwaysAllowed(
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
         * Exact match.
         */
        if (
            ALWAYS_ALLOWED_DOMAINS.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain match.
         */
        var current = normalized

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
                ALWAYS_ALLOWED_DOMAINS.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // USER ALLOWLIST
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

        /*
         * Built-in safety allowlist always wins.
         */
        if (
            isAlwaysAllowed(normalized)
        ) {
            return true
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
                    it
                        .trim()
                        .trim('.')
                        .lowercase(Locale.US)
                }
                .filter {
                    it.isNotEmpty()
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
         * Parent-domain allowlist.
         */
        var current = normalized

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
         * CRITICAL:
         *
         * Google/YouTube and user allowlist always
         * take priority over the block database.
         */
        if (
            isAlwaysAllowed(normalized) ||
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
         * Exact match first.
         */
        if (
            blockedHosts.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain matching.
         *
         * Example:
         *
         * ads.example.com
         *
         * matches:
         *
         * example.com
         *
         * but the protected domains above have already
         * been excluded.
         */
        var current = normalized

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
            .remove(KEY_BLOCKED_HOSTS)
            .remove(KEY_LAST_UPDATE)
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

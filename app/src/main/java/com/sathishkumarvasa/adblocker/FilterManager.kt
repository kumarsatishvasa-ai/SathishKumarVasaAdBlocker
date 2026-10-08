package com.sathishkumarvasa.adblocker

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.util.Locale

/**
 * DNS-oriented filter manager.
 *
 * IMPORTANT:
 * DNS blocking can block ad/tracker HOSTNAMES, but it cannot
 * remove advertisements that are served from the same hostname
 * as the actual content (for example some YouTube/Google traffic).
 *
 * This implementation is deliberately conservative around
 * Google/YouTube so normal search, login, video and API traffic
 * is not accidentally blocked.
 */
object FilterManager {

    private const val TAG = "FilterManager"

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    private const val MAX_HOSTS = 150_000

    private const val CONNECT_TIMEOUT_MS = 15_000

    private const val READ_TIMEOUT_MS = 30_000

    private const val MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024

    /**
     * DNS-compatible sources.
     *
     * EasyList:
     * advertising domains and common ad rules.
     *
     * EasyPrivacy:
     * trackers and analytics domains.
     */
    private val FILTER_LISTS = listOf(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
    )

    /**
     * Domains which should NEVER be blocked by this DNS filter.
     *
     * These are deliberately broad enough to protect:
     *
     * - Google Search
     * - YouTube
     * - Google login
     * - Google account services
     * - Google APIs
     * - YouTube media/API services
     *
     * Do not add ad domains here.
     */
    private val PROTECTED_SUFFIXES = setOf(
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googlevideo.com",
        "youtube.com",
        "youtube-nocookie.com",
        "ytimg.com",
        "ggpht.com",
        "googleadservices.com"
    )

    /**
     * A few extremely common browser/system services are also
     * protected from accidental blocking.
     */
    private val SAFE_EXACT_HOSTS = setOf(
        "dns.google",
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "clients4.google.com",
        "www.google.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtube.com"
    )

    // ============================================================
    // PUBLIC UPDATE
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        val newHosts =
            LinkedHashSet<String>()

        var successfulDownloads = 0

        try {

            for (url in FILTER_LISTS) {

                if (newHosts.size >= MAX_HOSTS) {
                    break
                }

                val text =
                    downloadFilterList(url)

                if (text.isBlank()) {

                    Log.w(
                        TAG,
                        "Empty filter list: $url"
                    )

                    continue
                }

                successfulDownloads++

                val parsed =
                    parseFilterList(text)

                for (host in parsed) {

                    if (newHosts.size >= MAX_HOSTS) {
                        break
                    }

                    if (
                        shouldKeepBlockedHost(
                            context,
                            host
                        )
                    ) {
                        newHosts.add(host)
                    }
                }

                Log.i(
                    TAG,
                    "Parsed ${parsed.size} DNS-compatible hosts from $url"
                )
            }

            /*
             * Add user/application custom rules.
             */
            addCustomRules(
                context,
                newHosts
            )

            /*
             * Never erase an existing working database when
             * downloads fail.
             */
            if (
                successfulDownloads == 0
            ) {

                Log.w(
                    TAG,
                    "No filter list downloaded. Existing database preserved."
                )

                return@withContext false
            }

            /*
             * A successful download producing zero hosts is
             * suspicious. Preserve the previous database.
             */
            if (
                newHosts.isEmpty()
            ) {

                Log.w(
                    TAG,
                    "No DNS rules produced. Existing database preserved."
                )

                return@withContext false
            }

            saveBlockedHosts(
                context,
                newHosts
            )

            updateStatistics(
                context,
                newHosts.size
            )

            Log.i(
                TAG,
                "DNS filter database updated: ${newHosts.size} hosts"
            )

            true

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Filter update failed. Existing database preserved.",
                e
            )

            false
        }
    }

    // ============================================================
    // CUSTOM RULES
    // ============================================================

    private fun addCustomRules(
        context: Context,
        hosts: MutableSet<String>
    ) {

        if (hosts.size >= MAX_HOSTS) {
            return
        }

        val customRules =
            try {

                AdBlockStorage
                    .getCustomRules(context)

            } catch (e: Exception) {

                Log.w(
                    TAG,
                    "Could not read custom rules",
                    e
                )

                emptySet<String>()
            }

        for (rule in customRules) {

            if (hosts.size >= MAX_HOSTS) {
                break
            }

            val host =
                extractHostname(rule)
                    ?: continue

            if (
                isValidHostname(host) &&
                shouldKeepBlockedHost(
                    context,
                    host
                )
            ) {
                hosts.add(host)
            }
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
                URI(url)
                    .toURL()
                    .openConnection()
                    as HttpURLConnection

            connection.connectTimeout =
                CONNECT_TIMEOUT_MS

            connection.readTimeout =
                READ_TIMEOUT_MS

            connection.requestMethod =
                "GET"

            connection.instanceFollowRedirects =
                true

            connection.useCaches =
                false

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

            val contentLength =
                connection.contentLengthLong

            if (
                contentLength > MAX_DOWNLOAD_BYTES
            ) {

                Log.w(
                    TAG,
                    "Filter list too large: $contentLength bytes"
                )

                return ""
            }

            val builder =
                StringBuilder()

            BufferedReader(
                InputStreamReader(
                    connection.inputStream,
                    Charsets.UTF_8
                )
            ).use { reader ->

                var totalBytes = 0

                while (true) {

                    val line =
                        reader.readLine()
                            ?: break

                    totalBytes +=
                        line.toByteArray(
                            Charsets.UTF_8
                        ).size + 1

                    if (
                        totalBytes >
                        MAX_DOWNLOAD_BYTES
                    ) {

                        Log.w(
                            TAG,
                            "Filter list exceeded download limit"
                        )

                        return ""
                    }

                    builder
                        .append(line)
                        .append('\n')
                }
            }

            builder.toString()

        } catch (e: Exception) {

            Log.w(
                TAG,
                "Could not download filter list: $url",
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
    // FILTER LIST PARSING
    // ============================================================

    private fun parseFilterList(
        text: String
    ): Set<String> {

        val hosts =
            LinkedHashSet<String>()

        BufferedReader(
            text.reader()
        ).use { reader ->

            while (true) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                val rawLine =
                    reader.readLine()
                        ?: break

                val host =
                    parseFilterLine(rawLine)
                        ?: continue

                if (
                    isValidHostname(host)
                ) {
                    hosts.add(host)
                }
            }
        }

        return hosts
    }

    // ============================================================
    // SINGLE RULE
    // ============================================================

    private fun parseFilterLine(
        rawLine: String
    ): String? {

        var line =
            rawLine
                .trim()
                .removePrefix("\uFEFF")

        if (line.isEmpty()) {
            return null
        }

        /*
         * Comments and list metadata.
         */
        if (
            line.startsWith("!") ||
            line.startsWith("#") ||
            line.startsWith("[")
        ) {
            return null
        }

        /*
         * Allow rules cannot safely be converted into a simple
         * DNS blocklist.
         */
        if (
            line.startsWith("@@")
        ) {
            return null
        }

        /*
         * Cosmetic/browser rules.
         *
         * They are intentionally ignored because this application
         * is a DNS filter, not a browser content-script engine.
         */
        if (
            line.contains("##") ||
            line.contains("#@#") ||
            line.contains("#?#") ||
            line.contains("#@?#") ||
            line.contains("#$#") ||
            line.contains("#@$#") ||
            line.contains("#%#")
        ) {
            return null
        }

        /*
         * Remove network-filter options.
         *
         * Example:
         *
         * ||ads.example.com^$script,image
         *
         * becomes:
         *
         * ||ads.example.com^
         */
        val dollarIndex =
            line.indexOf('$')

        if (dollarIndex >= 0) {

            line =
                line.substring(
                    0,
                    dollarIndex
                )
        }

        return extractHostname(line)
    }

    // ============================================================
    // HOSTNAME EXTRACTION
    // ============================================================

    private fun extractHostname(
        rule: String
    ): String? {

        var value =
            rule.trim()

        if (value.isEmpty()) {
            return null
        }

        /*
         * Hosts-file format:
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
            isHostsFileAddress(parts[0])
        ) {
            value = parts[1]
        }

        /*
         * ABP domain anchor:
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
         * URL scheme.
         */
        value =
            value.removePrefix(
                "https://"
            )

        value =
            value.removePrefix(
                "http://"
            )

        /*
         * Leading ABP anchor.
         */
        while (
            value.startsWith("|")
        ) {
            value =
                value.substring(1)
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
         * Remove path/query/fragment.
         */
        value =
            value.substringBefore('/')

        value =
            value.substringBefore('?')

        value =
            value.substringBefore('#')

        /*
         * Wildcards cannot be represented as a hostname.
         */
        if (
            value.contains("*") ||
            value.contains("%") ||
            value.contains("|")
        ) {
            return null
        }

        /*
         * Remove port if present.
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
         * Do not remove "www." here.
         *
         * Keeping the actual hostname is safer and avoids
         * accidentally changing the rule's meaning.
         */
        if (
            value.contains("://") ||
            value.contains("=") ||
            value.contains("&") ||
            value.contains(";") ||
            value.contains(",") ||
            value.contains("\"") ||
            value.contains("'") ||
            value.contains(" ")
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // PROTECTED DOMAINS
    // ============================================================

    private fun isProtectedHostname(
        hostname: String
    ): Boolean {

        val host =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (
            SAFE_EXACT_HOSTS.contains(host)
        ) {
            return true
        }

        for (suffix in PROTECTED_SUFFIXES) {

            if (
                host == suffix ||
                host.endsWith(
                    ".$suffix"
                )
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // SHOULD BLOCK
    // ============================================================

    private fun shouldKeepBlockedHost(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            normalizeHostname(hostname)
                ?: return false

        /*
         * FIRST SAFETY CHECK:
         *
         * Never create a blocking rule for protected
         * Google/YouTube infrastructure.
         */
        if (
            isProtectedHostname(normalized)
        ) {
            return false
        }

        /*
         * SECOND SAFETY CHECK:
         *
         * User allowlist always wins.
         */
        if (
            isAllowlisted(
                context,
                normalized
            )
        ) {
            return false
        }

        return true
    }

    // ============================================================
    // HOSTS ADDRESS
    // ============================================================

    private fun isHostsFileAddress(
        value: String
    ): Boolean {

        return value == "0.0.0.0" ||
            value == "127.0.0.1" ||
            value == "::" ||
            value == "::1"
    }

    // ============================================================
    // HOSTNAME VALIDATION
    // ============================================================

    private fun isValidHostname(
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
         * Local names should never be DNS blocked.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        /*
         * IP addresses are not hostname rules.
         */
        if (
            isIpv4Address(host) ||
            isIpv6Address(host)
        ) {
            return false
        }

        /*
         * Require a normal domain structure.
         */
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
    // IPV6
    // ============================================================

    private fun isIpv6Address(
        value: String
    ): Boolean {

        return value.contains(":")
    }

    // ============================================================
    // ALLOWLIST
    // ============================================================

    private fun getNormalizedAllowlist(
        context: Context
    ): Set<String> {

        return try {

            AdBlockStorage
                .getAllowlist(context)
                .mapNotNull {
                    normalizeHostname(it)
                }
                .toSet()

        } catch (e: Exception) {

            Log.w(
                TAG,
                "Could not read allowlist",
                e
            )

            emptySet()
        }
    }

    private fun isAllowlisted(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            normalizeHostname(hostname)
                ?: return false

        val allowlist =
            getNormalizedAllowlist(context)

        if (allowlist.isEmpty()) {
            return false
        }

        /*
         * Exact match.
         */
        if (
            allowlist.contains(normalized)
        ) {
            return true
        }

        /*
         * Parent-domain match.
         *
         * Example:
         *
         * allow example.com
         *
         * permits:
         * cdn.example.com
         * api.example.com
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
                allowlist.contains(current)
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // NORMALIZE
    // ============================================================

    private fun normalizeHostname(
        hostname: String
    ): String? {

        var value =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Permit users to enter:
         *
         * https://example.com
         * http://example.com/path
         */
        value =
            value.removePrefix(
                "https://"
            )

        value =
            value.removePrefix(
                "http://"
            )

        value =
            value.substringBefore('/')

        value =
            value.substringBefore('?')

        value =
            value.substringBefore('#')

        value =
            value.trim()
                .trim('.')

        if (
            !isValidHostname(value)
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // SAVE
    // ============================================================

    private fun saveBlockedHosts(
        context: Context,
        hosts: Set<String>
    ) {

        val copy =
            hosts.toSet()

        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                copy
            )
            .putLong(
                KEY_LAST_UPDATE,
                System.currentTimeMillis()
            )
            .apply()
    }

    // ============================================================
    // READ
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
    // CHECK BLOCKED
    // ============================================================

    fun isBlockedHost(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            normalizeHostname(hostname)
                ?: return false

        /*
         * NEVER block protected Google/YouTube infrastructure.
         */
        if (
            isProtectedHostname(normalized)
        ) {
            return false
        }

        /*
         * Allowlist wins.
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

        if (blockedHosts.isEmpty()) {
            return false
        }

        /*
         * Exact match first.
         */
        if (
            blockedHosts.contains(normalized)
        ) {
            return true
        }

        /*
         * Parent-domain matching.
         *
         * IMPORTANT:
         *
         * We do NOT walk all the way to an arbitrary public
         * suffix. We stop before the final TLD.
         *
         * Example:
         *
         * ads.example.com
         *
         * can match:
         * example.com
         *
         * but never:
         * com
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

            /*
             * Stop at a bare TLD.
             */
            if (
                current.indexOf('.') < 0
            ) {
                break
            }

            /*
             * Protected parent domains are always safe.
             */
            if (
                isProtectedHostname(current)
            ) {
                return false
            }

            if (
                blockedHosts.contains(current)
            ) {
                return true
            }
        }

        return false
    }

    // ============================================================
    // CLEAR
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

        Log.i(
            TAG,
            "DNS filter database cleared"
        )
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

    // ============================================================
    // STATISTICS
    // ============================================================

    private fun updateStatistics(
        context: Context,
        count: Int
    ) {

        try {

            AdBlockStorage.setRuleCount(
                context,
                count
            )

            AdBlockStorage.setLastUpdate(
                context
            )

        } catch (e: Exception) {

            Log.w(
                TAG,
                "Could not update filter statistics",
                e
            )
        }
    }

    // ============================================================
    // PREFERENCES
    // ============================================================

    private fun preferences(
        context: Context
    ) =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )
}

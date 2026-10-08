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
 * Important:
 * This converts browser filter rules into domain/hostname rules
 * suitable for DNS blocking.
 *
 * DNS filtering cannot reproduce all EasyList syntax. Cosmetic
 * rules, script rules, URL-path rules, and other browser-only
 * rules are intentionally ignored.
 */
object FilterManager {

    private const val TAG = "FilterManager"

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    /*
     * Keep the database reasonably sized for SharedPreferences.
     *
     * If you later move the database to Room/SQLite, this can
     * safely be increased substantially.
     */
    private const val MAX_HOSTS = 100_000

    private const val CONNECT_TIMEOUT_MS = 15_000

    private const val READ_TIMEOUT_MS = 30_000

    private const val MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024

    /*
     * These lists are converted into DNS hostname rules.
     */
    private val FILTER_LISTS = listOf(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
    )

    // ============================================================
    // PUBLIC UPDATE
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        val newHosts = LinkedHashSet<String>()

        var successfulDownloads = 0

        try {
            for (url in FILTER_LISTS) {

                if (newHosts.size >= MAX_HOSTS) {
                    break
                }

                val text = downloadFilterList(url)

                if (text.isBlank()) {
                    Log.w(
                        TAG,
                        "Empty filter list: $url"
                    )
                    continue
                }

                successfulDownloads++

                val parsed = parseFilterList(text)

                for (host in parsed) {

                    if (newHosts.size >= MAX_HOSTS) {
                        break
                    }

                    if (!isAllowlisted(context, host)) {
                        newHosts.add(host)
                    }
                }

                Log.i(
                    TAG,
                    "Parsed ${parsed.size} DNS hosts from $url"
                )
            }

            /*
             * Add application-specific custom rules.
             */
            addCustomRules(
                context = context,
                hosts = newHosts
            )

            /*
             * Never destroy a previously working filter database
             * simply because the network was unavailable.
             */
            if (
                successfulDownloads == 0 &&
                newHosts.isEmpty()
            ) {
                Log.w(
                    TAG,
                    "No filter list downloaded. Existing database preserved."
                )

                return@withContext false
            }

            /*
             * It is possible for a successful list to contain no
             * DNS-compatible rules. Do not erase a useful database
             * in that situation.
             */
            if (
                successfulDownloads > 0 &&
                newHosts.isEmpty()
            ) {
                Log.w(
                    TAG,
                    "Filter download succeeded but produced zero DNS hosts. Existing database preserved."
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

        val customRules = try {
            AdBlockStorage.getCustomRules(context)
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

            val host = extractHostname(rule)

            if (
                host != null &&
                isValidHostname(host) &&
                !isAllowlisted(context, host)
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

        var connection: HttpURLConnection? = null

        return try {

            connection =
                URI(url)
                    .toURL()
                    .openConnection() as HttpURLConnection

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
                        totalBytes > MAX_DOWNLOAD_BYTES
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
    // PARSE FILTER LIST
    // ============================================================

    private fun parseFilterList(
        text: String
    ): Set<String> {

        val hosts =
            LinkedHashSet<String>()

        val reader =
            text.reader()

        reader.forEachLine { rawLine ->

            if (hosts.size >= MAX_HOSTS) {
                return@forEachLine
            }

            val host =
                parseFilterLine(rawLine)

            if (
                host != null &&
                isValidHostname(host)
            ) {
                hosts.add(host)
            }
        }

        return hosts
    }

    // ============================================================
    // PARSE SINGLE RULE
    // ============================================================

    private fun parseFilterLine(
        rawLine: String
    ): String? {

        var line =
            rawLine.trim()

        if (line.isEmpty()) {
            return null
        }

        /*
         * BOM occasionally appears at the beginning of a file.
         */
        line =
            line.removePrefix("\uFEFF")

        /*
         * EasyList comments.
         */
        if (
            line.startsWith("!")
        ) {
            return null
        }

        /*
         * Hosts/filter metadata.
         */
        if (
            line.startsWith("[")
        ) {
            return null
        }

        /*
         * Exception rules cannot safely be represented by this
         * simple DNS blocklist.
         */
        if (
            line.startsWith("@@")
        ) {
            return null
        }

        /*
         * Cosmetic rules are browser-side rules.
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
         * Scriptlet rules and other extended syntax.
         */
        if (
            line.contains("##+") ||
            line.contains("#?#") ||
            line.contains("#@#+")
        ) {
            return null
        }

        /*
         * Remove inline comments occasionally found in
         * hosts-style lists.
         */
        if (line.startsWith("#")) {
            return null
        }

        /*
         * Network filter options.
         *
         * Example:
         *
         * ||ads.example.com^$script,image
         *
         * The domain before '$' can still be useful for DNS
         * blocking, so keep the part before the option.
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

        line =
            line.trim()

        if (line.isEmpty()) {
            return null
        }

        return extractHostname(line)
    }

    // ============================================================
    // EXTRACT HOSTNAME
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
         * Hosts-file syntax:
         *
         * 0.0.0.0 ads.example.com
         * 127.0.0.1 ads.example.com
         * :: ads.example.com
         * ::1 ads.example.com
         */
        val whitespaceParts =
            value.split(
                Regex("\\s+")
            )

        if (
            whitespaceParts.size >= 2 &&
            isHostsFileAddress(
                whitespaceParts[0]
            )
        ) {

            value =
                whitespaceParts[1]
        }

        /*
         * ABP hostname anchor.
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
         * Remove leading pipe anchors.
         */
        while (
            value.startsWith("|")
        ) {

            value =
                value.substring(1)
        }

        /*
         * ABP separator.
         *
         * ads.example.com^
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
         * Remove URL path.
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
         * DNS has no concept of wildcard hostnames.
         */
        if (
            value.contains("*") ||
            value.contains("%") ||
            value.contains("|")
        ) {
            return null
        }

        /*
         * Remove a port.
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
            value.trim()
                .trim('.')
                .removePrefix("www.")
                .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Reject values that clearly aren't hostnames.
         */
        if (
            value.contains("=") ||
            value.contains("&") ||
            value.contains(" ") ||
            value.contains(",") ||
            value.contains(";") ||
            value.contains("\"") ||
            value.contains("'")
        ) {
            return null
        }

        /*
         * Don't turn an entire URL into a hostname.
         */
        if (
            value.contains("://")
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // HOSTS FILE ADDRESS
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
    // VALIDATE HOSTNAME
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
         * Don't block local device names.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        /*
         * Don't store IP addresses as domain rules.
         */
        if (
            isIpv4Address(host)
        ) {
            return false
        }

        if (
            isIpv6Address(host)
        ) {
            return false
        }

        val labels =
            host.split(".")

        /*
         * DNS ad blocking is intended for domain names.
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

        /*
         * This is intentionally conservative.
         *
         * Hostnames cannot contain ':' anyway, so any value
         * containing ':' is treated as a non-host value.
         */
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
                .mapNotNull { entry ->

                    normalizeHostname(entry)
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
         * Exact allowlist match.
         */
        if (
            allowlist.contains(normalized)
        ) {
            return true
        }

        /*
         * Parent domain allowlisting.
         *
         * Allowing:
         *
         * example.com
         *
         * also allows:
         *
         * ads.example.com
         * cdn.example.com
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
    // NORMALIZE HOSTNAME
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
         * Handle accidental URL input in the allowlist.
         */
        value =
            value.removePrefix("https://")

        value =
            value.removePrefix("http://")

        value =
            value.substringBefore('/')

        value =
            value.substringBefore('?')

        value =
            value.substringBefore('#')

        value =
            value.trim()
                .trim('.')

        if (!isValidHostname(value)) {
            return null
        }

        return value
    }

    // ============================================================
    // SAVE DATABASE
    // ============================================================

    private fun saveBlockedHosts(
        context: Context,
        hosts: Set<String>
    ) {

        /*
         * Make a copy so SharedPreferences does not retain
         * a mutable set owned by another operation.
         */
        val immutableCopy =
            hosts.toSet()

        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                immutableCopy
            )
            .putLong(
                KEY_LAST_UPDATE,
                System.currentTimeMillis()
            )
            .apply()
    }

    // ============================================================
    // GET DATABASE
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
            normalizeHostname(hostname)
                ?: return false

        /*
         * Allowlist always wins.
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
         * Exact match.
         */
        if (
            blockedHosts.contains(normalized)
        ) {
            return true
        }

        /*
         * Parent-domain match.
         *
         * Example:
         *
         * query:
         * ad.doubleclick.example.com
         *
         * rule:
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

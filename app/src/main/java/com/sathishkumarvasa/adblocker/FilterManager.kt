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
 * This application is a DNS blocker, not a browser content blocker.
 *
 * Therefore this class intentionally accepts:
 *
 *   0.0.0.0 ads.example.com
 *   127.0.0.1 ads.example.com
 *   ||ads.example.com^
 *   ads.example.com
 *
 * and rejects:
 *
 *   cosmetic rules
 *   URL/path rules
 *   scriptlet rules
 *   CSS rules
 *   regex rules
 *   browser-only rules
 *
 * The resulting database contains hostnames only.
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
     * Keep the database reasonably sized.
     *
     * A DNS blocker does not need millions of browser rules.
     */
    private const val MAX_HOSTS = 150_000

    /*
     * DNS-oriented lists are much better suited to this application
     * than EasyList browser rules.
     *
     * StevenBlack hosts is a hosts-format list.
     * AdGuard DNS filter is primarily suitable for DNS filtering.
     */
    private val FILTER_LISTS = listOf(

        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"

    )

    // ============================================================
    // PUBLIC UPDATE
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val hosts =
                LinkedHashSet<String>(50_000)

            var successfulDownloads = 0

            Log.i(
                TAG,
                "Starting DNS filter update"
            )

            /*
             * Download DNS-compatible lists.
             */
            for (url in FILTER_LISTS) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                Log.i(
                    TAG,
                    "Downloading: $url"
                )

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
                    parseFilterList(
                        text
                    )

                Log.i(
                    TAG,
                    "Parsed ${parsed.size} hosts from $url"
                )

                for (host in parsed) {

                    if (hosts.size >= MAX_HOSTS) {
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
             * Add application-specific custom rules.
             */
            addCustomRules(
                context,
                hosts
            )

            /*
             * Do not destroy a working database if downloads failed.
             */
            if (
                successfulDownloads == 0
            ) {

                val existing =
                    getBlockedHosts(context)

                if (existing.isNotEmpty()) {

                    Log.w(
                        TAG,
                        "All filter downloads failed; keeping " +
                            "${existing.size} existing hosts"
                    )

                    return@withContext false
                }

                Log.w(
                    TAG,
                    "No filter list could be downloaded"
                )

                return@withContext false
            }

            /*
             * A successful download which produces zero rules
             * is suspicious. Do not replace the existing database.
             */
            if (hosts.isEmpty()) {

                Log.w(
                    TAG,
                    "Filter update produced zero hosts; " +
                        "keeping existing database"
                )

                return@withContext false
            }

            /*
             * Save atomically through SharedPreferences.
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

            } catch (e: Exception) {

                Log.w(
                    TAG,
                    "Could not update filter statistics",
                    e
                )
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
                "DNS filter update complete: " +
                    "${hosts.size} blocked hostnames"
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

                AdBlockStorage.getCustomRules(
                    context
                )

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
                extractHostFromRule(rule)

            if (
                host != null &&
                isValidDnsHostname(host) &&
                !isAllowlisted(
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
                (
                    URI(url)
                        .toURL()
                        .openConnection()
                        as HttpURLConnection
                    )

            connection.connectTimeout =
                20_000

            connection.readTimeout =
                45_000

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

            if (
                responseCode !in 200..299
            ) {

                Log.w(
                    TAG,
                    "HTTP $responseCode from $url"
                )

                return ""
            }

            BufferedReader(
                InputStreamReader(
                    connection.inputStream,
                    Charsets.UTF_8
                )
            ).use { reader ->

                val builder =
                    StringBuilder()

                while (true) {

                    val line =
                        reader.readLine()
                            ?: break

                    builder.append(line)
                    builder.append('\n')

                    /*
                     * Safety limit.
                     *
                     * Prevent a corrupted download from
                     * consuming excessive memory.
                     */
                    if (
                        builder.length >
                        25_000_000
                    ) {
                        Log.w(
                            TAG,
                            "Filter list exceeded size limit"
                        )

                        break
                    }
                }

                builder.toString()
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
    // PARSER
    // ============================================================

    private fun parseFilterList(
        text: String
    ): Set<String> {

        val hosts =
            LinkedHashSet<String>()

        val reader =
            text.lineSequence()

        for (rawLine in reader) {

            if (
                hosts.size >= MAX_HOSTS
            ) {
                break
            }

            val host =
                parseDnsRule(
                    rawLine
                )

            if (
                host != null
            ) {
                hosts.add(host)
            }
        }

        return hosts
    }

    // ============================================================
    // DNS RULE PARSER
    // ============================================================

    private fun parseDnsRule(
        rawLine: String
    ): String? {

        var line =
            rawLine.trim()

        if (line.isEmpty()) {
            return null
        }

        /*
         * Comments.
         */
        if (
            line.startsWith("#") ||
            line.startsWith("!")
        ) {
            return null
        }

        /*
         * List metadata.
         */
        if (
            line.startsWith("[")
        ) {
            return null
        }

        /*
         * AdGuard exception rule.
         *
         * Example:
         *
         * @@||example.com^
         */
        if (
            line.startsWith("@@")
        ) {
            return null
        }

        /*
         * Cosmetic/browser rules.
         */
        if (
            line.contains("##") ||
            line.contains("#@#") ||
            line.contains("#?#") ||
            line.contains("#@?#") ||
            line.contains("#$#") ||
            line.contains("#@$#") ||
            line.contains("#%#") ||
            line.contains("#@%#")
        ) {
            return null
        }

        /*
         * Scriptlet rules.
         */
        if (
            line.contains("##+js") ||
            line.contains("#?#")
        ) {
            return null
        }

        /*
         * Regex rules cannot be represented by DNS.
         */
        if (
            line.startsWith("/") &&
            line.endsWith("/")
        ) {
            return null
        }

        /*
         * Hosts format:
         *
         * 0.0.0.0 example.com
         * 127.0.0.1 example.com
         * :: example.com
         * ::1 example.com
         */
        val fields =
            line.split(
                Regex("\\s+")
            )

        if (
            fields.size >= 2 &&
            isHostsAddress(fields[0])
        ) {

            return normalizeHostname(
                fields[1]
            )
        }

        /*
         * Remove AdGuard/ABP options.
         *
         * Example:
         *
         * ||ads.example.com^$important
         */
        val dollar =
            line.indexOf('$')

        if (dollar >= 0) {

            line =
                line.substring(
                    0,
                    dollar
                )
        }

        line =
            line.trim()

        if (line.isEmpty()) {
            return null
        }

        /*
         * ABP domain rule:
         *
         * ||ads.example.com^
         */
        if (
            line.startsWith("||")
        ) {

            line =
                line.substring(2)

            val separator =
                line.indexOf('^')

            if (separator >= 0) {

                line =
                    line.substring(
                        0,
                        separator
                    )
            }

            return normalizeHostname(
                line
            )
        }

        /*
         * A bare hostname is accepted.
         *
         * Example:
         *
         * ads.example.com
         */
        if (
            looksLikePlainHostname(line)
        ) {

            return normalizeHostname(
                line
            )
        }

        return null
    }

    // ============================================================
    // HOST EXTRACTION
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
         * Hosts-file syntax.
         */
        val fields =
            value.split(
                Regex("\\s+")
            )

        if (
            fields.size >= 2 &&
            isHostsAddress(fields[0])
        ) {

            value =
                fields[1]
        }

        /*
         * ABP domain anchor.
         */
        if (
            value.startsWith("||")
        ) {
            value =
                value.substring(2)
        }

        /*
         * Remove options.
         */
        val dollar =
            value.indexOf('$')

        if (dollar >= 0) {

            value =
                value.substring(
                    0,
                    dollar
                )
        }

        /*
         * Remove scheme.
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
         * Remove leading separator.
         */
        value =
            value.removePrefix("|")

        /*
         * Remove ABP separator.
         */
        val separator =
            value.indexOf('^')

        if (separator >= 0) {

            value =
                value.substring(
                    0,
                    separator
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
         * Remove port.
         */
        val colon =
            value.lastIndexOf(':')

        if (
            colon > 0 &&
            value.indexOf(':') == colon
        ) {

            val possiblePort =
                value.substring(
                    colon + 1
                )

            if (
                possiblePort.toIntOrNull() != null
            ) {

                value =
                    value.substring(
                        0,
                        colon
                    )
            }
        }

        return normalizeHostname(
            value
        )
    }

    // ============================================================
    // NORMALIZE HOST
    // ============================================================

    private fun normalizeHostname(
        hostname: String
    ): String? {

        var value =
            hostname
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        /*
         * Hosts files occasionally contain:
         *
         * localhost
         * broadcasthost
         * ip6-...
         */
        if (value.isEmpty()) {
            return null
        }

        /*
         * Remove surrounding brackets from IPv6.
         */
        if (
            value.startsWith("[") &&
            value.endsWith("]")
        ) {
            return null
        }

        /*
         * Never treat an IP address as a DNS hostname rule.
         */
        if (
            isIpv4Address(value) ||
            value.contains(":")
        ) {
            return null
        }

        /*
         * www.example.com is still a legitimate
         * hostname, so do NOT remove www.
         */
        if (
            !isValidDnsHostname(value)
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // HOSTNAME VALIDATION
    // ============================================================

    private fun isValidDnsHostname(
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
         * Local/private names should not be globally blocked.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local") ||
            host.endsWith(".localdomain")
        ) {
            return false
        }

        /*
         * Ignore IPv4.
         */
        if (
            isIpv4Address(host)
        ) {
            return false
        }

        /*
         * Ignore obvious wildcard/ABP syntax.
         */
        if (
            host.contains("*") ||
            host.contains("|") ||
            host.contains("^") ||
            host.contains("/") ||
            host.contains("\\") ||
            host.contains("%") ||
            host.contains("=") ||
            host.contains("&") ||
            host.contains(",") ||
            host.contains(" ")
        ) {
            return false
        }

        val labels =
            host.split(".")

        /*
         * A DNS ad-blocking hostname normally has
         * at least two labels.
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

    private fun looksLikePlainHostname(
        value: String
    ): Boolean {

        if (
            value.contains("/") ||
            value.contains("^") ||
            value.contains("|") ||
            value.contains("*") ||
            value.contains("$") ||
            value.contains(" ")
        ) {
            return false
        }

        return isValidDnsHostname(
            value
                .trim()
                .trim('.')
                .lowercase(Locale.US)
        )
    }

    // ============================================================
    // HOSTS ADDRESS
    // ============================================================

    private fun isHostsAddress(
        value: String
    ): Boolean {

        return value == "0.0.0.0" ||
            value == "127.0.0.1" ||
            value == "::" ||
            value == "::1"
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

            /*
             * Avoid accepting things like:
             *
             * 01
             * 001
             *
             * as DNS hostnames.
             */
            if (
                part.length > 3
            ) {
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

                emptySet<String>()
            }

        if (allowlist.isEmpty()) {
            return false
        }

        val normalizedAllowlist =
            allowlist
                .mapNotNull {

                    val value =
                        it.trim()
                            .trim('.')
                            .lowercase(Locale.US)

                    if (
                        isValidDnsHostname(value)
                    ) {
                        value
                    } else {
                        null
                    }
                }
                .toSet()

        /*
         * Exact allow.
         */
        if (
            normalizedAllowlist.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain allow.
         *
         * example.com
         *
         * also allows:
         *
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

        /*
         * Copy the set before putting it into SharedPreferences.
         */
        val safeCopy =
            hosts
                .map {
                    it.trim()
                        .trim('.')
                        .lowercase(Locale.US)
                }
                .filter {
                    isValidDnsHostname(it)
                }
                .toSet()

        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                safeCopy
            )
            .apply()
    }

    // ============================================================
    // GET HOST DATABASE
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
    // BLOCK CHECK
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

        if (
            normalized.isEmpty()
        ) {
            return false
        }

        /*
         * Never block invalid/local hostnames.
         */
        if (
            !isValidDnsHostname(
                normalized
            )
        ) {
            return false
        }

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

        val blocked =
            getBlockedHosts(
                context
            )

        /*
         * Exact match.
         */
        if (
            blocked.contains(
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
         * blocked:
         * ads.example.com
         *
         * query:
         * banner.ads.example.com
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
                blocked.contains(
                    current
                )
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
    // DATABASE SIZE
    // ============================================================

    fun getBlockedHostCount(
        context: Context
    ): Int {

        return getBlockedHosts(
            context
        ).size
    }

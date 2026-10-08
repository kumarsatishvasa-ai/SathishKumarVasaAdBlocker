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
 * DNS-oriented ad/tracker filter manager.
 *
 * Design goals:
 *
 * 1. Keep Chrome + Google Search + YouTube connectivity working.
 * 2. Only create DNS hostname rules.
 * 3. Ignore cosmetic/browser-only EasyList rules.
 * 4. Never block Google/YouTube infrastructure from downloaded lists.
 * 5. Fail open when the filter database cannot be updated/read.
 * 6. Preserve an existing working database if a download fails.
 *
 * IMPORTANT:
 *
 * DNS blocking cannot reliably remove every YouTube advertisement.
 * YouTube can use the same infrastructure for advertisements and
 * normal video/content traffic. Blocking large Google/YouTube
 * infrastructure domains can therefore break YouTube.
 */
object FilterManager {

    private const val TAG = "FilterManager"

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    private const val MAX_HOSTS = 100_000

    private const val CONNECT_TIMEOUT_MS = 15_000

    private const val READ_TIMEOUT_MS = 30_000

    private const val MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024

    /*
     * DNS-compatible public filter lists.
     */
    private val FILTER_LISTS = listOf(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
    )

    /*
     * Domains that must NEVER be blocked by the DNS filter.
     *
     * These are deliberately limited to infrastructure needed by
     * Google Search, Chrome's Google services and YouTube.
     *
     * The allowlist is checked against the queried hostname and
     * all of its parent domains.
     */
    private val PROTECTED_DOMAINS = setOf(

        // --------------------------------------------------------
        // Google core
        // --------------------------------------------------------

        "google.com",
        "google.co.in",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googlevideo.com",

        // --------------------------------------------------------
        // Google authentication / accounts
        // --------------------------------------------------------

        "accounts.google.com",
        "accounts.google.co.in",
        "myaccount.google.com",

        // --------------------------------------------------------
        // Google Search
        // --------------------------------------------------------

        "www.google.com",
        "www.google.co.in",
        "www.googleapis.com",

        // --------------------------------------------------------
        // Google static/service infrastructure
        // --------------------------------------------------------

        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "ssl.gstatic.com",
        "apis.google.com",
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "clients5.google.com",

        // --------------------------------------------------------
        // YouTube
        // --------------------------------------------------------

        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",

        // YouTube API / player
        "youtubei.googleapis.com",
        "youtube.googleapis.com",

        // YouTube images/thumbnails
        "ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",

        // YouTube video delivery
        "googlevideo.com",

        // YouTube related services
        "youtu.be",
        "youtubeeducation.com",

        // --------------------------------------------------------
        // Google telemetry/service endpoints that can be required
        // by Chrome/Google services.
        // --------------------------------------------------------

        "gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "gvt5.com",
        "gvt6.com",

        // --------------------------------------------------------
        // Chrome update/service infrastructure
        // --------------------------------------------------------

        "googleusercontent.com",
        "chrome.com",
        "chromium.org"
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

                    /*
                     * Protected Google/YouTube infrastructure always
                     * wins over downloaded filter rules.
                     */
                    if (isProtectedHost(host)) {
                        continue
                    }

                    if (
                        !isAllowlisted(
                            context,
                            host
                        )
                    ) {
                        newHosts.add(host)
                    }
                }

                Log.i(
                    TAG,
                    "Parsed ${parsed.size} DNS hosts from $url"
                )
            }

            /*
             * Add user-defined custom rules.
             *
             * Protected Google/YouTube domains are still protected.
             */
            addCustomRules(
                context = context,
                hosts = newHosts
            )

            /*
             * If every download failed, preserve the existing
             * database rather than replacing it with an empty one.
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
             * A successful download that produces zero rules is
             * not considered a reason to destroy a working database.
             */
            if (newHosts.isEmpty()) {

                Log.w(
                    TAG,
                    "Filter download succeeded but produced zero DNS rules. Existing database preserved."
                )

                return@withContext false
            }

            /*
             * Always remove protected hosts before saving.
             *
             * This is an additional safety layer.
             */
            val safeHosts =
                newHosts
                    .filterNot {
                        isProtectedHost(it)
                    }
                    .toSet()

            saveBlockedHosts(
                context,
                safeHosts
            )

            updateStatistics(
                context,
                safeHosts.size
            )

            Log.i(
                TAG,
                "DNS filter database updated: ${safeHosts.size} hosts"
            )

            true

        } catch (e: Exception) {

            /*
             * FAIL OPEN.
             *
             * An error updating the filter list must never cause
             * Chrome, Google Search or YouTube to stop working.
             */
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

                emptySet()
            }

        for (rule in customRules) {

            if (hosts.size >= MAX_HOSTS) {
                break
            }

            val host =
                extractHostname(rule)
                    ?: continue

            if (
                !isValidHostname(host)
            ) {
                continue
            }

            /*
             * Never allow a custom rule to accidentally block
             * Google/YouTube infrastructure.
             */
            if (
                isProtectedHost(host)
            ) {
                Log.d(
                    TAG,
                    "Ignoring protected custom rule: $host"
                )

                continue
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

            if (
                responseCode !in 200..299
            ) {

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

            if (
                hosts.size >= MAX_HOSTS
            ) {
                return@forEachLine
            }

            val host =
                parseFilterLine(rawLine)
                    ?: return@forEachLine

            if (
                isValidHostname(host)
            ) {

                /*
                 * Filter protected domains before they ever enter
                 * the candidate database.
                 */
                if (
                    !isProtectedHost(host)
                ) {
                    hosts.add(host)
                }
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
         * Remove BOM.
         */
        line =
            line.removePrefix("\uFEFF")

        /*
         * Comments.
         */
        if (
            line.startsWith("!")
        ) {
            return null
        }

        if (
            line.startsWith("#")
        ) {
            return null
        }

        /*
         * Filter metadata.
         */
        if (
            line.startsWith("[")
        ) {
            return null
        }

        /*
         * Exception rules are deliberately ignored here.
         *
         * DNS cannot safely reproduce every browser-level
         * exception rule.
         */
        if (
            line.startsWith("@@")
        ) {
            return null
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
            line.contains("#@$#") ||
            line.contains("#%#")
        ) {
            return null
        }

        /*
         * Scriptlet and extended rules.
         */
        if (
            line.contains("##+") ||
            line.contains("#@#+")
        ) {
            return null
        }

        /*
         * Network options.
         *
         * Example:
         *
         * ||ads.example.com^$script,image
         *
         * Keep the hostname portion.
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
         * Hosts-file syntax.
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
         * Remove schemes.
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
         * Remove leading filter anchors.
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
         * URL path.
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
         * Query.
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
         * Fragment.
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
         * DNS cannot represent wildcard hostnames.
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
            value
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Reject obvious non-host values.
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

        if (
            value.contains("://")
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // PROTECTED HOSTS
    // ============================================================

    private fun isProtectedHost(
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
         * Exact protected match.
         */
        if (
            PROTECTED_DOMAINS.contains(
                normalized
            )
        ) {
            return true
        }

        /*
         * Parent-domain protected match.
         *
         * Example:
         *
         * foo.youtube.com
         *
         * is protected by:
         *
         * youtube.com
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
                PROTECTED_DOMAINS.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
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
         * Never block local device names.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        /*
         * Never store IP addresses as hostname rules.
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
         * DNS ad blocking should operate on domain names.
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

        if (
            allowlist.isEmpty()
        ) {
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
            value
                .trim()
                .trim('.')

        if (
            !isValidHostname(value)
        ) {
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
         * Make an immutable copy before passing it to
         * SharedPreferences.
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
         * ABSOLUTE SAFETY RULE:
         *
         * Google/YouTube infrastructure is never blocked by this
         * filter manager.
         */
        if (
            isProtectedHost(normalized)
        ) {
            return false
        }

        /*
         * User allowlist wins.
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

        if (
            blockedHosts.isEmpty()
        ) {
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
         * ads.tracker.example.com
         *
         * can match:
         *
         * tracker.example.com
         *
         * but protected Google/YouTube domains were already
         * rejected above.
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
             * Never allow a parent-domain match to cross into
             * protected infrastructure.
             */
            if (
                isProtectedHost(current)
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

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
 * Conservative DNS filter manager.
 *
 * Goals:
 * 1. Keep Google Search working.
 * 2. Keep YouTube home working.
 * 3. Keep YouTube video playback working.
 * 4. Block DNS-level advertising/tracking domains where possible.
 *
 * IMPORTANT:
 * DNS filtering cannot reliably remove all YouTube video ads.
 * YouTube can deliver advertisements through infrastructure
 * that is also required for normal video playback.
 *
 * Therefore Google/YouTube media infrastructure is explicitly
 * protected from blocking.
 */
object FilterManager {

    private const val TAG = "FilterManager"

    private const val PREFS_NAME =
        "sathish_kumar_vasa_adblocker_filters"

    private const val KEY_BLOCKED_HOSTS =
        "blocked_hosts"

    private const val KEY_LAST_UPDATE =
        "last_update"

    private const val MAX_HOSTS =
        100_000

    private const val CONNECT_TIMEOUT_MS =
        15_000

    private const val READ_TIMEOUT_MS =
        30_000

    private const val MAX_DOWNLOAD_BYTES =
        20 * 1024 * 1024

    /**
     * Conservative filter sources.
     */
    private val FILTER_LISTS =
        listOf(
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt"
        )

    /**
     * Domains that MUST NEVER be blocked by this DNS layer.
     *
     * These are intentionally broad because breaking one of these
     * can break Google Search, YouTube login, playback, thumbnails,
     * captions, or other normal Google functionality.
     */
    private val PROTECTED_SUFFIXES =
        setOf(
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "googleusercontent.com",
            "googlevideo.com",
            "youtube.com",
            "youtube-nocookie.com",
            "ytimg.com",
            "ggpht.com"
        )

    /**
     * Known advertising/tracking infrastructure that can safely
     * be treated as DNS-level advertising in most cases.
     *
     * This list is intentionally small and conservative.
     */
    private val SAFE_AD_HOSTS =
        setOf(
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "adservice.google.com",
            "adsrvr.org",
            "adnxs.com",
            "advertising.com",
            "pubmatic.com",
            "rubiconproject.com",
            "criteo.com",
            "scorecardresearch.com",
            "zedo.com",
            "taboola.com",
            "outbrain.com",
            "quantserve.com",
            "moatads.com",
            "amazon-adsystem.com",
            "casalemedia.com",
            "openx.net",
            "smartadserver.com",
            "33across.com",
            "contextweb.com",
            "sharethrough.com",
            "indexww.com",
            "lijit.com"
        )

    // ============================================================
    // UPDATE FILTERS
    // ============================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        val newHosts =
            LinkedHashSet<String>()

        var successfulDownloads =
            0

        try {

            /*
             * Add our conservative known ad/tracker domains first.
             */
            for (host in SAFE_AD_HOSTS) {

                if (
                    newHosts.size >= MAX_HOSTS
                ) {
                    break
                }

                if (
                    !isProtectedHostname(host) &&
                    !isAllowlisted(context, host)
                ) {
                    newHosts.add(host)
                }
            }

            /*
             * Download EasyList/EasyPrivacy.
             *
             * Only DNS-compatible hostname rules are retained.
             */
            for (url in FILTER_LISTS) {

                if (
                    newHosts.size >= MAX_HOSTS
                ) {
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

                    if (
                        newHosts.size >= MAX_HOSTS
                    ) {
                        break
                    }

                    /*
                     * Critical safety check:
                     *
                     * Never allow an imported filter rule to
                     * override our Google/YouTube protection.
                     */
                    if (
                        isProtectedHostname(host)
                    ) {
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
                    "Parsed ${parsed.size} DNS rules from $url"
                )
            }

            /*
             * Custom rules are also subjected to the same
             * Google/YouTube protection.
             */
            addCustomRules(
                context,
                newHosts
            )

            /*
             * Never erase a working database because a download
             * failed.
             */
            if (
                successfulDownloads == 0 &&
                newHosts.isEmpty()
            ) {

                Log.w(
                    TAG,
                    "No filter source available. Existing database preserved."
                )

                return@withContext false
            }

            if (
                newHosts.isEmpty()
            ) {

                Log.w(
                    TAG,
                    "No safe DNS rules generated. Existing database preserved."
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
                "DNS database updated: ${newHosts.size} hosts"
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

        if (
            hosts.size >= MAX_HOSTS
        ) {
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

            if (
                hosts.size >= MAX_HOSTS
            ) {
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
             * Never permit custom rules to break YouTube/Google.
             */
            if (
                isProtectedHostname(host)
            ) {
                Log.w(
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
                contentLength >
                MAX_DOWNLOAD_BYTES
            ) {

                Log.w(
                    TAG,
                    "Filter list too large"
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

                var totalBytes =
                    0

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
                            "Filter list exceeded size limit"
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

        text.reader().forEachLine { rawLine ->

            if (
                hosts.size >= MAX_HOSTS
            ) {
                return@forEachLine
            }

            val host =
                parseFilterLine(rawLine)
                    ?: return@forEachLine

            if (
                !isValidHostname(host)
            ) {
                return@forEachLine
            }

            /*
             * This is the most important protection in this file.
             */
            if (
                isProtectedHostname(host)
            ) {
                return@forEachLine
            }

            hosts.add(host)
        }

        return hosts
    }

    // ============================================================
    // PARSE SINGLE FILTER RULE
    // ============================================================

    private fun parseFilterLine(
        rawLine: String
    ): String? {

        var line =
            rawLine
                .trim()
                .removePrefix("\uFEFF")

        if (
            line.isEmpty()
        ) {
            return null
        }

        if (
            line.startsWith("!")
        ) {
            return null
        }

        if (
            line.startsWith("[")
        ) {
            return null
        }

        if (
            line.startsWith("@@")
        ) {
            return null
        }

        /*
         * Cosmetic/content rules cannot be safely converted
         * into DNS rules.
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

        if (
            line.startsWith("#")
        ) {
            return null
        }

        /*
         * Network filter options.
         *
         * Example:
         *
         * ||ads.example.com^$script,image
         *
         * Keep only the hostname portion.
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

        if (
            line.isEmpty()
        ) {
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

        if (
            value.isEmpty()
        ) {
            return null
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
            isHostsFileAddress(parts[0])
        ) {

            value =
                parts[1]
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

        value =
            value.removePrefix("http://")
                .removePrefix("https://")

        while (
            value.startsWith("|")
        ) {

            value =
                value.substring(1)
        }

        /*
         * ABP separator.
         */
        val separator =
            value.indexOf('^')

        if (
            separator >= 0
        ) {

            value =
                value.substring(
                    0,
                    separator
                )
        }

        /*
         * Anything after a path is not part of the DNS name.
         */
        val slash =
            value.indexOf('/')

        if (
            slash >= 0
        ) {

            value =
                value.substring(
                    0,
                    slash
                )
        }

        val question =
            value.indexOf('?')

        if (
            question >= 0
        ) {

            value =
                value.substring(
                    0,
                    question
                )
        }

        val fragment =
            value.indexOf('#')

        if (
            fragment >= 0
        ) {

            value =
                value.substring(
                    0,
                    fragment
                )
        }

        /*
         * DNS rules cannot safely represent wildcards.
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
        val colon =
            value.indexOf(':')

        if (
            colon >= 0
        ) {

            value =
                value.substring(
                    0,
                    colon
                )
        }

        value =
            value
                .trim()
                .trim('.')
                .lowercase(Locale.US)

        /*
         * Do NOT remove www. here.
         *
         * www.example.com and example.com are different DNS
         * names and should be handled independently.
         */
        if (
            value.isEmpty()
        ) {
            return null
        }

        if (
            value.contains("=") ||
            value.contains("&") ||
            value.contains(" ") ||
            value.contains(",") ||
            value.contains(";") ||
            value.contains("\"") ||
            value.contains("'") ||
            value.contains("://")
        ) {
            return null
        }

        return value
    }

    // ============================================================
    // PROTECTED GOOGLE/YOUTUBE DOMAINS
    // ============================================================

    private fun isProtectedHostname(
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
         * Exact or child-domain match.
         *
         * Example:
         *
         * google.com             protected
         * www.google.com         protected
         * accounts.google.com    protected
         * youtube.com            protected
         * www.youtube.com        protected
         * r1---sn-....googlevideo.com protected
         */
        for (suffix in PROTECTED_SUFFIXES) {

            if (
                normalized == suffix ||
                normalized.endsWith(
                    ".$suffix"
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

        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host.endsWith(".local")
        ) {
            return false
        }

        if (
            isIpv4Address(host) ||
            host.contains(":")
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

        if (
            parts.size != 4
        ) {
            return false
        }

        for (part in parts) {

            if (
                part.isEmpty()
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
            normalizeHostname(hostname)
                ?: return false

        val allowlist =
            try {

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

        if (
            allowlist.isEmpty()
        ) {
            return false
        }

        if (
            allowlist.contains(normalized)
        ) {
            return true
        }

        var current =
            normalized

        while (true) {

            val dot =
                current.indexOf('.')

            if (
                dot < 0
            ) {
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

        value =
            value
                .removePrefix("https://")
                .removePrefix("http://")

        value =
            value
                .substringBefore('/')
                .substringBefore('?')
                .substringBefore('#')
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
    // SAVE
    // ============================================================

    private fun saveBlockedHosts(
        context: Context,
        hosts: Set<String>
    ) {

        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                hosts.toSet()
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
         * FIRST safety check.
         *
         * Google/YouTube can never be blocked by this manager.
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
         * Parent-domain matching.
         *
         * Before blocking a parent domain, check that the
         * parent itself is not protected.
         */
        var current =
            normalized

        while (true) {

            val dot =
                current.indexOf('.')

            if (
                dot < 0
            ) {
                break
            }

            current =
                current.substring(
                    dot + 1
                )

            /*
             * Never allow a parent rule to reach Google/YouTube.
             */
            if (
                isProtectedHostname(current)
            ) {
                break
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
                "Could not update statistics",
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

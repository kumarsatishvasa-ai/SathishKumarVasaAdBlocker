package com.sathishkumarvasa.adblocker

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI

object FilterManager {

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

    /*
     * Network lists used by the DNS blocker.
     *
     * Important:
     * This implementation converts network/domain rules into
     * hostnames. Cosmetic browser rules such as ##selector are
     * intentionally ignored because a VPN/DNS blocker cannot
     * remove webpage elements.
     */
    private val filterLists =
        listOf(
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt"
        )

    // =====================================================
    // UPDATE FILTERS
    // =====================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val hosts =
                LinkedHashSet<String>()

            var successfulDownloads =
                0

            // -------------------------------------------------
            // Download filter lists
            // -------------------------------------------------

            for (url in filterLists) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                val text =
                    downloadFilterList(url)

                if (text.isBlank()) {
                    continue
                }

                successfulDownloads++

                val parsed =
                    parseFilterList(text)

                for (host in parsed) {

                    if (hosts.size >= MAX_HOSTS) {
                        break
                    }

                    hosts.add(host)
                }
            }

            // -------------------------------------------------
            // Add custom rules
            // -------------------------------------------------

            val customRules =
                AdBlockStorage.getCustomRules(
                    context
                )

            for (rule in customRules) {

                if (hosts.size >= MAX_HOSTS) {
                    break
                }

                val host =
                    extractHostFromRule(
                        rule
                    )

                if (
                    host != null &&
                    isValidHost(host)
                ) {
                    hosts.add(host)
                }
            }

            /*
             * If every download failed and there are no custom
             * rules, preserve the existing database.
             */
            if (
                successfulDownloads == 0 &&
                hosts.isEmpty()
            ) {
                return@withContext false
            }

            // -------------------------------------------------
            // Save
            // -------------------------------------------------

            saveBlockedHosts(
                context,
                hosts
            )

            AdBlockStorage.setRuleCount(
                context,
                hosts.size
            )

            AdBlockStorage.setLastUpdate(
                context
            )

            preferences(context)
                .edit()
                .putLong(
                    KEY_LAST_UPDATE,
                    System.currentTimeMillis()
                )
                .apply()

            true

        } catch (error: Exception) {

            error.printStackTrace()

            false
        }
    }

    // =====================================================
    // DOWNLOAD FILTER LIST
    // =====================================================

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
                CONNECT_TIMEOUT_MS

            connection.readTimeout =
                READ_TIMEOUT_MS

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
                return ""
            }

            connection.inputStream
                .bufferedReader(
                    Charsets.UTF_8
                )
                .use {
                    it.readText()
                }

        } catch (error: Exception) {

            error.printStackTrace()

            ""

        } finally {

            connection?.disconnect()
        }
    }

    // =====================================================
    // PARSE FILTER LIST
    // =====================================================

    private fun parseFilterList(
        text: String
    ): Set<String> {

        val hosts =
            LinkedHashSet<String>()

        for (rawLine in text.lineSequence()) {

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

            // Comments.
            if (
                line.startsWith("!")
            ) {
                continue
            }

            // Metadata.
            if (
                line.startsWith("[")
            ) {
                continue
            }

            // ABP exception rules.
            if (
                line.startsWith("@@")
            ) {
                continue
            }

            /*
             * Cosmetic rules cannot be enforced by DNS.
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
             * Host-file format:
             *
             * 0.0.0.0 example.com
             * 127.0.0.1 example.com
             */
            val hostFileHost =
                parseHostsFileLine(
                    line
                )

            if (
                hostFileHost != null &&
                isValidHost(hostFileHost)
            ) {
                hosts.add(hostFileHost)
                continue
            }

            /*
             * Remove ABP options:
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

            /*
             * Ignore rules that are primarily URL/path based.
             * The DNS blocker only needs the hostname.
             */
            val host =
                extractHostFromRule(
                    line
                )

            if (
                host != null &&
                isValidHost(host)
            ) {
                hosts.add(host)
            }
        }

        return hosts
    }

    // =====================================================
    // HOSTS FILE PARSER
    // =====================================================

    private fun parseHostsFileLine(
        line: String
    ): String? {

        val cleaned =
            line
                .substringBefore('#')
                .trim()

        if (cleaned.isEmpty()) {
            return null
        }

        val parts =
            cleaned.split(
                Regex("\\s+")
            )

        if (parts.size < 2) {
            return null
        }

        val first =
            parts[0]

        /*
         * Only treat it as a hosts-file rule if the first
         * field is an IPv4/IPv6 loopback/block address.
         */
        if (
            first != "0.0.0.0" &&
            first != "127.0.0.1" &&
            first != "::" &&
            first != "::1"
        ) {
            return null
        }

        for (
            index in 1 until parts.size
        ) {

            val candidate =
                parts[index]
                    .trim()
                    .lowercase()

            if (
                isValidHost(candidate)
            ) {
                return candidate
            }
        }

        return null
    }

    // =====================================================
    // EXTRACT HOST
    // =====================================================

    private fun extractHostFromRule(
        rule: String
    ): String? {

        var value =
            rule.trim()

        if (value.isEmpty()) {
            return null
        }

        /*
         * ABP domain anchor:
         *
         * ||example.com^
         */
        if (
            value.startsWith("||")
        ) {
            value =
                value.substring(2)
        }

        /*
         * Remove leading single URL separator.
         */
        value =
            value.trimStart('|')

        /*
         * Remove scheme.
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
         * Remove credentials if a URL-like rule was supplied.
         */
        val atIndex =
            value.lastIndexOf('@')

        if (atIndex >= 0) {
            value =
                value.substring(
                    atIndex + 1
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
         * Remove query/fragment.
         */
        value =
            value.substringBefore('?')

        value =
            value.substringBefore('#')

        /*
         * Wildcards cannot be stored as DNS hostnames.
         */
        if (
            value.contains("*") ||
            value.contains("|") ||
            value.contains("%")
        ) {
            return null
        }

        /*
         * Remove trailing dots.
         */
        value =
            value.trim('.')

        /*
         * IPv4 addresses are not useful as domain filters.
         */
        if (
            value.matches(
                Regex(
                    "^\\d{1,3}(\\.\\d{1,3}){3}$"
                )
            )
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

        /*
         * Reject obvious non-hostname syntax.
         */
        if (
            value.contains("=") ||
            value.contains("&") ||
            value.contains(" ") ||
            value.contains("(") ||
            value.contains(")") ||
            value.contains("[") ||
            value.contains("]")
        ) {
            return null
        }

        value =
            value
                .trim()
                .lowercase()

        if (value.isEmpty()) {
            return null
        }

        /*
         * If the rule accidentally contains a leading dot,
         * normalize it.
         */
        value =
            value.trim('.')

        return value
    }

    // =====================================================
    // HOST VALIDATION
    // =====================================================

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
         * Local/pseudo hostnames should not be blocked.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain" ||
            host == "local"
        ) {
            return false
        }

        /*
         * Require a domain suffix.
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

            for (
                character in label
            ) {

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

    // =====================================================
    // PREFERENCES
    // =====================================================

    private fun preferences(
        context: Context
    ) =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    // =====================================================
    // SAVE
    // =====================================================

    private fun saveBlockedHosts(
        context: Context,
        hosts: Set<String>
    ) {

        /*
         * SharedPreferences StringSet is not ideal for very
         * large databases. For this version we keep the same
         * storage design as the rest of the application.
         */
        preferences(context)
            .edit()
            .putStringSet(
                KEY_BLOCKED_HOSTS,
                hosts
            )
            .apply()
    }

    // =====================================================
    // GET BLOCKED HOSTS
    // =====================================================

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

    // =====================================================
    // HOST MATCHING
    // =====================================================

    fun isBlockedHost(
        context: Context,
        hostname: String
    ): Boolean {

        val normalized =
            hostname
                .trim()
                .lowercase()
                .trim('.')

        if (
            normalized.isEmpty()
        ) {
            return false
        }

        /*
         * Allowlist has priority over blocking.
         */
        if (
            isAllowlisted(
                context,
                normalized
            )
        ) {
            return false
        }

        val hosts =
            getBlockedHosts(context)

        /*
         * Exact hostname.
         */
        if (
            hosts.contains(normalized)
        ) {
            return true
        }

        /*
         * Parent-domain matching.
         *
         * ads.example.com
         *

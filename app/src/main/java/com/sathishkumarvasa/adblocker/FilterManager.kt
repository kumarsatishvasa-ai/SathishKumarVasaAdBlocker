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

    private val filterLists =
        listOf(
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt"
        )


    // =====================================================
    // PUBLIC UPDATE FUNCTION
    // =====================================================

    suspend fun updateFilters(
        context: Context
    ): Boolean = withContext(Dispatchers.IO) {

        try {

            val hosts =
                LinkedHashSet<String>()

            var successfulDownloads = 0

            // -------------------------------------------------
            // Download EasyList / EasyPrivacy
            // -------------------------------------------------

            for (url in filterLists) {

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

                if (hosts.size >= MAX_HOSTS) {
                    break
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
                    extractHostFromRule(rule)

                if (host != null) {
                    hosts.add(host)
                }
            }


            /*
             * Don't destroy a working filter database if
             * every download failed and there are no custom
             * rules available.
             */
            if (
                successfulDownloads == 0 &&
                hosts.isEmpty()
            ) {
                return@withContext false
            }


            // -------------------------------------------------
            // Save filters
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
    // DOWNLOAD
    // =====================================================

    private fun downloadFilterList(
        url: String
    ): String {

        var connection:
            HttpURLConnection? = null

        return try {

            connection =
                (URI(url)
                    .toURL()
                    .openConnection()
                    as HttpURLConnection)

            connection.connectTimeout =
                15_000

            connection.readTimeout =
                30_000

            connection.requestMethod =
                "GET"

            connection.setRequestProperty(
                "User-Agent",
                "SathishKumarVasaAdBlocker/1.0"
            )

            connection.setRequestProperty(
                "Accept",
                "text/plain,*/*"
            )

            connection.instanceFollowRedirects =
                true


            val responseCode =
                connection.responseCode


            if (
                responseCode !in 200..299
            ) {
                return ""
            }


            connection.inputStream
                .bufferedReader()
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
    // PARSE ADBLOCK LIST
    // =====================================================

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

            if (hosts.size >= MAX_HOSTS) {
                break
            }


            var line =
                rawLine.trim()


            if (line.isEmpty()) {
                continue
            }


            // Comments.
            if (line.startsWith("!")) {
                continue
            }


            // Filter-list metadata.
            if (line.startsWith("[")) {
                continue
            }


            /*
             * ABP exception rules:
             *
             * @@||example.com^
             *
             * These cannot simply be represented by our
             * host-only VPN database, so ignore them here.
             */
            if (line.startsWith("@@")) {
                continue
            }


            /*
             * Cosmetic filters modify page elements rather
             * than network requests.
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
             * Split ABP options.
             *
             * Example:
             *
             * ||ads.example.com^$script,image
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
         * Remove ABP beginning anchor.
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
         * Remove URL scheme.
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
         * Remove www.
         */
        value =
            value.removePrefix(
                "www."
            )


        /*
         * The filter may contain a path.
         *
         * example.com/ads/banner.js
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
         *
         * example.com^
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
         * Wildcards are not directly usable as DNS
         * hostnames.
         */
        if (
            value.contains("*") ||
            value.contains("|")
        ) {
            return null
        }


        /*
         * Remove trailing dots.
         */
        value =
            value.trim('.')


        /*
         * A filter may contain query/string matching
         * syntax that isn't a hostname.
         */
        if (
            value.contains("?") ||
            value.contains("=") ||
            value.contains("&") ||
            value.contains(" ")
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


        /*
         * Lowercase for consistent matching.
         */
        value =
            value.lowercase()


        if (
            value.isEmpty()
        ) {
            return null
        }


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
         * Don't accidentally block localhost/private
         * pseudo-hostnames from malformed filters.
         */
        if (
            host == "localhost" ||
            host == "localhost.localdomain"
        ) {
            return false
        }


        val labels =
            host.split(".")


        if (labels.size < 2) {
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


    // =====================================================
    // STORAGE
    // =====================================================

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


    // =====================================================
    // READ FILTERS
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


        if (normalized.isEmpty()) {
            return false
        }


        val hosts =
            getBlockedHosts(context)


        /*
         * Check the exact hostname first.
         */
        if (
            hosts.contains(normalized)
        ) {
            return true
        }


        /*
         * Check parent domains.
         *
         * Example:
         *
         * ads.example.com
         *
         * can match:
         *
         * example.com
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
                hosts.contains(current)
            ) {
                return true
            }
        }


        return false
    }


    // =====================================================
    // CLEAR FILTERS
    // =====================================================

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


        AdBlockStorage.setRuleCount(
            context,
            0
        )
    }


    // =====================================================
    // LAST UPDATE
    // =====================================================

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

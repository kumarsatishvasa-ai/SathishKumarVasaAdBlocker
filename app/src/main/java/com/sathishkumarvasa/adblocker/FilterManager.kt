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

/*
 * These are DNS/network filter lists.
 *
 * Important:
 * EasyList/EasyPrivacy contain many browser-level rules
 * that cannot be represented by a DNS-only blocker.
 *
 * We therefore extract only hostname-compatible rules.
 */
private val filterLists =
    listOf(
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt"
    )

suspend fun updateFilters(
    context: Context
): Boolean = withContext(Dispatchers.IO) {

    try {
        val hosts =
            LinkedHashSet<String>()

        var successfulDownloads = 0

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

            val parsedHosts =
                parseFilterList(text)

            for (host in parsedHosts) {

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
         * If downloads failed completely and there are no
         * custom rules, preserve the previously downloaded
         * database instead of replacing it with an empty set.
         */
        if (
            successfulDownloads == 0 &&
            hosts.isEmpty() &&
            getBlockedHosts(context).isNotEmpty()
        ) {
            return@withContext false
        }

        /*
         * If nothing was downloaded and no rules exist,
         * don't destroy an existing filter database.
         */
        if (
            successfulDownloads == 0 &&
            hosts.isEmpty()
        ) {
            return@withContext false
        }

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

        /*
         * Comments.
         */
        if (
            line.startsWith("!")
        ) {
            continue
        }

        /*
         * Filter-list metadata.
         */
        if (
            line.startsWith("[")
        ) {
            continue
        }

        /*
         * ABP exception rules.
         *
         * Example:
         * @@||example.com^
         *
         * A DNS host-only filter cannot accurately
         * reproduce these exceptions, so skip them.
         */
        if (
            line.startsWith("@@")
        ) {
            continue
        }

        /*
         * Cosmetic/browser-element rules do not belong
         * in a DNS hostname database.
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

private fun extractHostFromRule(
    rule: String
): String? {

    var value =
        rule.trim()

    if (value.isEmpty()) {
        return null
    }

    /*
     * Remove ABP domain anchor.
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
     * Hosts-file style:
     *
     * 0.0.0.0 ads.example.com
     * 127.0.0.1 ads.example.com
     */
    val whitespace =
        value.split(
            Regex("\\s+")
        )

    if (
        whitespace.size >= 2 &&
        (
            whitespace[0] == "0.0.0.0" ||
            whitespace[0] == "127.0.0.1" ||
            whitespace[0] == "::" ||
            whitespace[0] == "::1"
        )
    ) {
        value =
            whitespace[1]
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
     * Remove leading www.
     */
    value =
        value.removePrefix(
            "www."
        )

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
     * Remove ABP separator.
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
     * Remove query/fragment.
     */
    val queryIndex =
        value.indexOf('?')

    if (
        queryIndex >= 0
    ) {
        value =
            value.substring(
                0,
                queryIndex
            )
    }

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
     * Wildcard rules cannot be directly represented
     * as DNS hostnames.
     */
    if (
        value.contains("*") ||
        value.contains("|") ||
        value.contains("%")
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
            .lowercase()

    if (value.isEmpty()) {
        return null
    }

    /*
     * Reject values that clearly are not hostnames.
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
     * Do not block local pseudo-hostnames.
     */
    if (
        host == "localhost" ||
        host == "localhost.localdomain" ||
        host.endsWith(".local")
    ) {
        return false
    }

    /*
     * Reject IP addresses.
     */
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

private fun isAllowlisted(
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

    val allowlist =
        AdBlockStorage.getAllowlist(
            context
        )

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

    val hosts =
        getBlockedHosts(context)

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
     * matches:
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

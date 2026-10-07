package com.sathishkumarvasa.adblocker

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * DNS-level filtering engine.
 *
 * It decides whether a hostname should be blocked.
 *
 * Important:
 * A DNS filter sees hostnames, not complete HTTPS URLs.
 * Therefore rules depending on URL paths are reduced to
 * their hostname/domain component where possible.
 */
class DnsFilter(
    private val preferences: AppPreferences
) {

    private val rules =
        ArrayList<FilterRule>()

    private val blockedDomains =
        ConcurrentHashMap.newKeySet<String>()

    private val allowlist =
        ConcurrentHashMap.newKeySet<String>()

    private val cache =
        ConcurrentHashMap<String, Boolean>()

    @Synchronized
    fun replaceRules(
        newRules: List<FilterRule>
    ) {

        rules.clear()

        rules.addAll(
            newRules
        )

        rebuildDomainIndex()

        clearCache()
    }

    @Synchronized
    fun loadRules(
        newRules: List<FilterRule>
    ) {
        replaceRules(newRules)
    }

    @Synchronized
    fun clearRules() {

        rules.clear()

        blockedDomains.clear()

        clearCache()
    }

    fun ruleCount(): Int {
        return rules.size
    }

    fun isBlocked(
        hostname: String
    ): Boolean {

        if (
            !preferences.enabled.value
        ) {
            return false
        }

        val host =
            normalizeHostname(
                hostname
            )

        if (host.isEmpty()) {
            return false
        }

        /*
         * Never block localhost/private infrastructure
         * by accident.
         */
        if (
            isLocalHostname(host)
        ) {
            return false
        }

        /*
         * User allowlist has priority.
         */
        if (
            preferences.isAllowlisted(host)
        ) {
            return false
        }

        /*
         * Fast cache.
         */
        cache[host]?.let {
            return it
        }

        /*
         * Fast exact/domain lookup.
         */
        if (
            matchesBlockedDomain(host)
        ) {

            cache[host] = true

            return true
        }

        /*
         * Check parsed rules.
         */
        val result =
            rules.any { rule ->

                matchesRule(
                    rule,
                    host
                )
            }

        cache[host] =
            result

        return result
    }

    /**
     * Returns a DNS response address that can be used
     * for blocked domains.
     *
     * We use 0.0.0.0 for IPv4 and :: for IPv6.
     */
    fun blockedIpv4(): ByteArray {
        return byteArrayOf(
            0,
            0,
            0,
            0
        )
    }

    fun blockedIpv6(): ByteArray {
        return ByteArray(16)
    }

    fun normalizeHostname(
        hostname: String
    ): String {

        var host =
            hostname
                .trim()
                .lowercase()

        /*
         * Remove trailing DNS dot.
         */
        host =
            host.trimEnd('.')

        /*
         * Remove brackets around IPv6.
         */
        if (
            host.startsWith("[") &&
            host.endsWith("]")
        ) {
            host =
                host.substring(
                    1,
                    host.length - 1
                )
        }

        /*
         * A hostname should never contain URL
         * path/query components.
         */
        host =
            host.substringBefore('/')

        host =
            host.substringBefore('?')

        host =
            host.substringBefore('#')

        return host
    }

    private fun rebuildDomainIndex() {

        blockedDomains.clear()

        for (
            rule in rules
        ) {

            val domain =
                extractBlockingDomain(
                    rule.pattern
                )

            if (
                domain.isNotEmpty()
            ) {
                blockedDomains.add(
                    domain
                )
            }
        }
    }

    private fun extractBlockingDomain(
        pattern: String
    ): String {

        var value =
            pattern.trim().lowercase()

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

            /*
             * Stop at ABP separator.
             */
            value =
                value.substringBefore('^')

            /*
             * Stop at URL path.
             */
            value =
                value.substringBefore('/')

            /*
             * Stop at query.
             */
            value =
                value.substringBefore('?')

            /*
             * If there are wildcards in the remaining
             * value, exact domain indexing isn't safe.
             */
            if (
                value.contains("*") ||
                value.contains("|")
            ) {
                return ""
            }

            /*
             * Remove a leading wildcard.
             */
            value =
                value.trim('*')

            if (
                isValidDomain(value)
            ) {
                return value
            }

            return ""
        }

        /*
         * Exact hostname style rules:
         *
         * example.com
         */
        if (
            !value.contains("/") &&
            !value.contains("*") &&
            !value.contains("^") &&
            isValidDomain(value)
        ) {
            return value
        }

        return ""
    }

    private fun matchesBlockedDomain(
        hostname: String
    ): Boolean {

        /*
         * Check the hostname itself.
         */
        if (
            blockedDomains.contains(
                hostname
            )
        ) {
            return true
        }

        /*
         * Check parent domains.
         *
         * Example:
         *
         * cdn.ads.example.com
         *
         * checks:
         *
         * cdn.ads.example.com
         * ads.example.com
         * example.com
         */
        var current =
            hostname

        while (
            current.contains('.')
        ) {

            current =
                current.substringAfter(
                    '.'
                )

            if (
                blockedDomains.contains(
                    current
                )
            ) {
                return true
            }
        }

        return false
    }

    private fun matchesRule(
        rule: FilterRule,
        hostname: String
    ): Boolean {

        /*
         * DNS has no resource-type information.
         *
         * If the rule is explicitly restricted to a
         * browser resource type, we cannot know that
         * information here.
         *
         * For domain-level protection we therefore
         * evaluate the rule if it has at least one
         * supported network resource type.
         */
        if (
            rule.resourceTypes.isEmpty()
        ) {
            return false
        }

        if (
            !rule.appliesToDomain(hostname)
        ) {
            return false
        }

        if (
            matchesDomainType(
                rule,
                hostname
            ).not()
        ) {
            /*
             * DNS alone cannot reliably determine
             * first-party/third-party relationship.
             *
             * DomainType rules are therefore treated
             * conservatively here.
             */
            return false
        }

        return matchesPattern(
            rule.pattern,
            hostname
        )
    }

    private fun matchesDomainType(
        rule: FilterRule,
        hostname: String
    ): Boolean {

        return when (
            rule.domainType
        ) {

            DomainType.ANY ->
                true

            /*
             * DNS has no referring-page context.
             *
             * We cannot reliably determine whether
             * a DNS lookup is first-party or third-party.
             *
             * These are deliberately not treated as
             * universal blocking rules.
             */
            DomainType.FIRST_PARTY ->
                false

            DomainType.THIRD_PARTY ->
                true
        }
    }

    private fun matchesPattern(
        pattern: String,
        hostname: String
    ): Boolean {

        var value =
            pattern
                .trim()
                .lowercase()

        if (value.isEmpty()) {
            return false
        }

        /*
         * ||domain^ is the most important EasyList form.
         */
        if (
            value.startsWith("||")
        ) {

            value =
                value.substring(2)

            val end =
                value.indexOfAny(
                    charArrayOf(
                        '^',
                        '/',
                        '?',
                        '*'
                    )
                )

            val domain =
                if (end >= 0) {
                    value.substring(
                        0,
                        end
                    )
                } else {
                    value
                }

            if (
                domain.isEmpty()
            ) {
                return false
            }

            return (
                hostname == domain ||
                    hostname.endsWith(
                        ".$domain"
                    )
            )
        }

        /*
         * |example.com|
         */
        if (
            value.startsWith("|") &&
            value.endsWith("|")
        ) {

            value =
                value.substring(
                    1,
                    value.length - 1
                )

            return hostname == value
        }

        /*
         * Remove simple URL separators.
         */
        value =
            value.trim('|')

        /*
         * Exact domain.
         */
        if (
            isValidDomain(value)
        ) {

            return (
                hostname == value ||
                    hostname.endsWith(
                        ".$value"
                    )
            )
        }

        /*
         * Wildcard pattern.
         *
         * We only apply this to the hostname.
         */
        if (
            value.contains("*")
        ) {

            val regex =
                wildcardToRegex(
                    value
                )

            return regex.matches(
                hostname
            )
        }

        /*
         * If the pattern contains a path,
         * DNS cannot see that path.
         *
         * Extract the first recognizable hostname
         * and compare it.
         */
        val hostCandidate =
            extractHostnameFromPattern(
                value
            )

        if (
            hostCandidate.isNotEmpty()
        ) {

            return (
                hostname ==
                    hostCandidate ||
                    hostname.endsWith(
                        ".$hostCandidate"
                    )
            )
        }

        return false
    }

    private fun extractHostnameFromPattern(
        pattern: String
    ): String {

        var value =
            pattern

        value =
            value.removePrefix(
                "http://"
            )

        value =
            value.removePrefix(
                "https://"
            )

        value =
            value.trimStart('|')

        value =
            value.substringBefore('/')

        value =
            value.substringBefore('^')

        value =
            value.substringBefore('?')

        value =
            value.trim('*')

        return if (
            isValidDomain(value)
        ) {
            value
        } else {
            ""
        }
    }

    private fun wildcardToRegex(
        pattern: String
    ): Regex {

        val escaped =
            Regex.escape(
                pattern
            )

        val regex =
            escaped.replace(
                "\\*",
                ".*"
            )

        return Regex(
            "^$regex$",
            RegexOption.IGNORE_CASE
        )
    }

    private fun isValidDomain(
        value: String
    ): Boolean {

        if (
            value.isEmpty() ||
            value.length > 253
        ) {
            return false
        }

        if (
            value.contains('/') ||
            value.contains(':') ||
            value.contains('?') ||
            value.contains('#') ||
            value.contains(' ')
        ) {
            return false
        }

        return value.split('.').all { label ->

            label.isNotEmpty() &&
                label.length <= 63 &&
                label.first() != '-' &&
                label.last() != '-' &&
                label.all {
                    it.isLetterOrDigit() ||
                        it == '-'
                }
        }
    }

    private fun isLocalHostname(
        hostname: String
    ): Boolean {

        if (
            hostname == "localhost"
        ) {
            return true
        }

        if (
            hostname.endsWith(
                ".localhost"
            )
        ) {
            return true
        }

        if (
            hostname.endsWith(
                ".local"
            )
        ) {
            return true
        }

        /*
         * IP address.
         */
        return try {

            InetAddress
                .getByName(hostname)
                .isLoopbackAddress

        } catch (
            _: Exception
        ) {

            false
        }
    }

    private fun clearCache() {
        cache.clear()
    }
}


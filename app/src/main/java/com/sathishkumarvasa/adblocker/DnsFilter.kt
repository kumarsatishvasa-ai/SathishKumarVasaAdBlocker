package com.sathishkumarvasa.adblocker

class DnsFilter(
    private val preferences: AppPreferences
) {

    @Volatile
    private var rules: List<FilterRule> =
        emptyList()

    fun loadRules(
        newRules: List<FilterRule>
    ) {

        rules =
            newRules
                .filter {
                    it.pattern.isNotBlank()
                }
                .sortedByDescending {
                    it.priority
                }
    }

    fun normalizeHostname(
        hostname: String
    ): String {

        var value =
            hostname
                .trim()
                .lowercase()

        /*
         * DNS names normally arrive without a trailing
         * dot, but accept and normalize one if present.
         */
        value =
            value.trim('.')

        /*
         * Remove accidental whitespace.
         */
        if (
            value.any {
                it.isWhitespace()
            }
        ) {
            return ""
        }

        /*
         * DNS hostnames should not contain URL
         * components.
         */
        if (
            value.contains("/") ||
            value.contains("\\") ||
            value.contains(":") ||
            value.contains("?") ||
            value.contains("#")
        ) {
            return ""
        }

        return value
    }

    fun isBlocked(
        hostname: String,
        resourceType: ResourceType =
            ResourceType.OTHER
    ): Boolean {

        val normalized =
            normalizeHostname(
                hostname
            )

        if (
            normalized.isEmpty()
        ) {
            return false
        }

        /*
         * User allowlist always wins.
         */
        if (
            preferences.isAllowlisted(
                normalized
            )
        ) {
            return false
        }

        val currentRules =
            rules

        if (
            currentRules.isEmpty()
        ) {
            return false
        }

        /*
         * A DNS request does not expose the exact
         * browser resource type. OTHER is therefore
         * used as the generic DNS resource type.
         *
         * Rules that explicitly contain OTHER are
         * checked normally. Rules containing all
         * resource types also match.
         */
        for (
            rule in currentRules
        ) {

            if (
                !rule.appliesToDomain(
                    normalized
                )
            ) {
                continue
            }

            if (
                !resourceTypeMatches(
                    rule,
                    resourceType
                )
            ) {
                continue
            }

            if (
                matchesPattern(
                    normalized,
                    rule.normalizedPattern()
                )
            ) {
                return true
            }
        }

        return false
    }

    private fun resourceTypeMatches(
        rule: FilterRule,
        resourceType: ResourceType
    ): Boolean {

        /*
         * DNS filtering has no HTTP resource metadata.
         *
         * Treat a rule containing OTHER as applicable.
         *
         * Rules containing the complete resource set are
         * also applicable.
         */
        if (
            rule.resourceTypes.contains(
                ResourceType.OTHER
            )
        ) {
            return true
        }

        if (
            rule.resourceTypes.contains(
                resourceType
            )
        ) {
            return true
        }

        /*
         * Most domain-only EasyList rules have all
         * resource types. This fallback keeps those rules
         * effective for DNS filtering.
         */
        return rule.resourceTypes.containsAll(
            ResourceType.entries.toSet()
        )
    }

    private fun matchesPattern(
        hostname: String,
        pattern: String
    ): Boolean {

        var value =
            pattern.trim()

        if (
            value.isEmpty()
        ) {
            return false
        }

        /*
         * ABP exception rules are not loaded by
         * AdblockParser, but protect against them here too.
         */
        if (
            value.startsWith("@@")
        ) {
            return false
        }

        /*
         * Remove URL scheme when present.
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
         * Handle ABP domain anchor.
         *
         * ||example.com^
         *
         * means the domain example.com or a subdomain.
         */
        if (
            value.startsWith("||")
        ) {

            return matchesDomainAnchor(
                hostname,
                value.substring(2)
            )
        }

        /*
         * Handle beginning anchor.
         */
        if (
            value.startsWith("|")
        ) {

            value =
                value.removePrefix("|")
        }

        /*
         * Handle ending anchor.
         */
        val endAnchored =
            value.endsWith("|")

        if (endAnchored) {
            value =
                value.removeSuffix("|")
        }

        if (
            value.isEmpty()
        ) {
            return false
        }

        /*
         * Convert the supported ABP pattern syntax
         * into a simple matcher.
         */
        val regex =
            buildRegexFromPattern(
                value,
                endAnchored
            )
                ?: return false

        return try {

            Regex(
                regex,
                setOf(
                    RegexOption.IGNORE_CASE
                )
            ).containsMatchIn(
                hostname
            )

        } catch (_: Exception) {

            false
        }
    }

    private fun matchesDomainAnchor(
        hostname: String,
        rawPattern: String
    ): Boolean {

        var pattern =
            rawPattern.trim()

        if (
            pattern.isEmpty()
        ) {
            return false
        }

        /*
         * Remove an ABP separator at the end.
         *
         * ||doubleclick.net^
         *
         * becomes:
         *
         * doubleclick.net
         */
        if (
            pattern.endsWith("^")
        ) {
            pattern =
                pattern.dropLast(1)
        }

        /*
         * Domain-anchor patterns may contain path
         * components. For DNS filtering we only have
         * the hostname, so compare the hostname portion.
         */
        pattern =
            pattern
                .substringBefore("/")
                .trim('.')

        if (
            pattern.isEmpty()
        ) {
            return false
        }

        /*
         * Wildcards inside a domain are supported.
         */
        if (
            pattern.contains("*")
        ) {

            val regex =
                buildRegexFromDomain(
                    pattern
                )

            return try {

                Regex(
                    regex,
                    RegexOption.IGNORE_CASE
                ).matches(
                    hostname
                )

            } catch (_: Exception) {

                false
            }
        }

        return hostname == pattern ||
            hostname.endsWith(
                ".$pattern"
            )
    }

    private fun buildRegexFromDomain(
        pattern: String
    ): String {

        val builder =
            StringBuilder()

        builder.append("^")

        for (
            character in pattern
        ) {

            when (character) {

                '*' ->
                    builder.append(
                        ".*"
                    )

                '.' ->
                    builder.append(
                        "\\."
                    )

                else ->
                    builder.append(
                        Regex.escape(
                            character.toString()
                        )
                    )
            }
        }

        builder.append("$")

        return builder.toString()
    }

    private fun buildRegexFromPattern(
        pattern: String,
        endAnchored: Boolean
    ): String? {

        val builder =
            StringBuilder()

        /*
         * A hostname is what we are matching, not a
         * complete URL.
         */
        builder.append("^")

        var index =
            0

        while (
            index < pattern.length
        ) {

            val character =
                pattern[index]

            when {

                /*
                 * ABP wildcard.
                 */
                character == '*' -> {

                    builder.append(
                        ".*"
                    )
                }

                /*
                 * ABP separator character.
                 *
                 * ^ matches a URL separator. For DNS
                 * filtering, the useful interpretation is
                 * a hostname boundary.
                 */
                character == '^' -> {

                    builder.append(
                        "(?:\\.|$)"
                    )
                }

                /*
                 * Escape regex metacharacters.
                 */
                character == '.' -> {

                    builder.append(
                        "\\."
                    )
                }

                character == '?' -> {

                    builder.append(
                        "\\?"
                    )
                }

                character == '+' -> {

                    builder.append(
                        "\\+"
                    )
                }

                character == '(' -> {

                    builder.append(
                        "\\("
                    )
                }

                character == ')' -> {

                    builder.append(
                        "\\)"
                    )
                }

                character == '[' -> {

                    builder.append(
                        "\\["
                    )
                }

                character == ']' -> {

                    builder.append(
                        "\\]"
                    )
                }

                character == '{' -> {

                    builder.append(
                        "\\{"
                    )
                }

                character == '}' -> {

                    builder.append(
                        "\\}"
                    )
                }

                character == '\\' -> {

                    builder.append(
                        "\\\\"
                    )
                }

                character == '$' -> {

                    builder.append(
                        "\\$"
                    )
                }

                else -> {

                    builder.append(
                        Regex.escape(
                            character.toString()
                        )
                    )
                }
            }

            index++
        }

        if (
            endAnchored
        ) {
            builder.append("$")
        } else {
            /*
             * A plain hostname pattern should be allowed
             * to match the hostname as a substring.
             */
            builder.append(
                ".*"
            )
        }

        return builder.toString()
    }

    fun ruleCount(): Int {
        return rules.size
    }

    fun clearRules() {
        rules = emptyList()
    }
}

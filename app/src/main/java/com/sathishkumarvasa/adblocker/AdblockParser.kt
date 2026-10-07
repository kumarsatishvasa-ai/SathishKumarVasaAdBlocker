package com.sathishkumarvasa.adblocker

/**
 * Partial Adblock Plus / EasyList parser.
 *
 * This intentionally focuses on network blocking rules that
 * can be represented by the Android DNS filtering engine.
 *
 * Cosmetic filters, regex filters, redirects, CSP,
 * removeparam, replace and similar browser-specific actions
 * are ignored.
 */
class AdblockParser(
    private val maxRules: Int = DEFAULT_MAX_RULES
) {

    fun parse(
        text: String,
        source: String = "unknown"
    ): List<FilterRule> {

        if (text.isBlank()) {
            return emptyList()
        }

        val result =
            ArrayList<FilterRule>(
                minOf(
                    maxRules,
                    4096
                )
            )

        for (
            rawLine in text.lineSequence()
        ) {

            if (result.size >= maxRules) {
                break
            }

            val line =
                rawLine.trim()

            if (line.isEmpty()) {
                continue
            }

            val rule =
                parseLine(
                    line,
                    source
                )

            if (rule != null) {
                result.add(rule)
            }
        }

        return result
    }

    fun parseLine(
        line: String,
        source: String = "custom"
    ): FilterRule? {

        var value =
            line.trim()

        if (value.isEmpty()) {
            return null
        }

        /*
         * Comments.
         */
        if (
            value.startsWith("!") ||
            value.startsWith("[")
        ) {
            return null
        }

        /*
         * Exception rules are not blocking rules.
         *
         * Examples:
         *
         * @@||example.com^
         * @@||ads.example.com^$script
         */
        if (value.startsWith("@@")) {
            return null
        }

        /*
         * Cosmetic filtering.
         *
         * Examples:
         *
         * example.com##.advertisement
         * example.com##+js(...)
         */
        if (
            value.contains("##") ||
            value.contains("#@#") ||
            value.contains("#?#") ||
            value.contains("#@?#") ||
            value.contains("#$#") ||
            value.contains("#@$#")
        ) {
            return null
        }

        /*
         * Regex filters:
         *
         * /advertisement[0-9]+/
         */
        if (
            value.length >= 2 &&
            value.startsWith("/") &&
            value.endsWith("/")
        ) {
            return null
        }

        var pattern =
            value

        var optionString =
            ""

        val dollarIndex =
            findOptionSeparator(value)

        if (dollarIndex >= 0) {

            pattern =
                value.substring(
                    0,
                    dollarIndex
                )

            optionString =
                value.substring(
                    dollarIndex + 1
                )
        }

        pattern =
            pattern.trim()

        if (pattern.isEmpty()) {
            return null
        }

        if (pattern.length > 1500) {
            return null
        }

        /*
         * This DNS engine does not support whitespace
         * inside a URL filter.
         */
        if (pattern.any { it.isWhitespace() }) {
            return null
        }

        /*
         * ABP's separator character.
         *
         * We preserve '^' because it is meaningful to
         * our pattern matcher.
         */
        pattern =
            normalizePattern(pattern)
                ?: return null

        val parsedOptions =
            parseOptions(
                optionString
            )
                ?: return null

        val resourceTypes =
            if (
                parsedOptions.positiveResourceTypes
                    .isNotEmpty()
            ) {
                parsedOptions
                    .positiveResourceTypes
                    .toSet()
            } else if (
                parsedOptions
                    .excludedResourceTypes
                    .isNotEmpty()
            ) {

                ResourceType.entries
                    .filter {
                        !parsedOptions
                            .excludedResourceTypes
                            .contains(it)
                    }
                    .toSet()

            } else {

                ResourceType.entries
                    .toSet()
            }

        if (resourceTypes.isEmpty()) {
            return null
        }

        /*
         * Avoid rules that are too broad.
         */
        if (
            pattern.length < 3 ||
            pattern == "*" ||
            pattern == "http" ||
            pattern == "https"
        ) {
            return null
        }

        return FilterRule(
            pattern = pattern,
            resourceTypes = resourceTypes,
            includedDomains =
                parsedOptions.includedDomains,
            excludedDomains =
                parsedOptions.excludedDomains,
            domainType =
                parsedOptions.domainType,
            priority =
                parsedOptions.priority,
            important =
                parsedOptions.important,
            source = source
        )
    }

    private fun findOptionSeparator(
        value: String
    ): Int {

        /*
         * In normal ABP syntax the first '$' separates
         * the URL pattern from its options.
         *
         * A '$' inside a regex is already excluded above.
         */
        return value.indexOf('$')
    }

    private fun normalizePattern(
        pattern: String
    ): String? {

        var value =
            pattern.trim()

        if (value.isEmpty()) {
            return null
        }

        /*
         * The Android matcher works with ASCII URL
         * patterns for predictable behavior.
         */
        if (
            value.any {
                it.code > 127
            }
        ) {
            return null
        }

        /*
         * Collapse repeated ABP separators.
         *
         * ^^^ -> ^
         */
        value =
            value.replace(
                Regex("\\^{2,}"),
                "^"
            )

        /*
         * Remove surrounding whitespace.
         */
        value =
            value.trim()

        return value.ifEmpty {
            null
        }
    }

    private fun parseOptions(
        optionString: String
    ): ParsedOptions? {

        if (optionString.isBlank()) {
            return ParsedOptions()
        }

        val positiveTypes =
            LinkedHashSet<ResourceType>()

        val excludedTypes =
            LinkedHashSet<ResourceType>()

        val includedDomains =
            LinkedHashSet<String>()

        val excludedDomains =
            LinkedHashSet<String>()

        var domainType =
            DomainType.ANY

        var priority =
            1

        var important =
            false

        val options =
            optionString
                .split(',')
                .map {
                    it.trim()
                }
                .filter {
                    it.isNotEmpty()
                }

        for (option in options) {

            if (option.isEmpty()) {
                continue
            }

            /*
             * Resource type exclusions.
             *
             * Example:
             *
             * $~script
             */
            if (
                option.startsWith("~")
            ) {

                val type =
                    resourceTypeFor(
                        option.substring(1)
                    )

                if (type != null) {
                    excludedTypes.add(type)
                    continue
                }

                /*
                 * ~third-party is handled below.
                 */
                if (
                    option == "~third-party"
                ) {
                    domainType =
                        DomainType.FIRST_PARTY

                    continue
                }

                /*
                 * Unknown negative options are ignored.
                 */
                continue
            }

            /*
             * Positive resource type.
             */
            resourceTypeFor(
                option
            )?.let {

                positiveTypes.add(it)

                continue
            }

            /*
             * Domain restriction.
             *
             * Example:
             *
             * $domain=youtube.com|google.com
             */
            if (
                option.startsWith(
                    "domain="
                )
            ) {

                val domains =
                    parseDomainList(
                        option.substring(
                            "domain=".length
                        )
                    )

                if (
                    domains.first.isNotEmpty()
                ) {

                    includedDomains.addAll(
                        domains.first
                    )
                }

                if (
                    domains.second.isNotEmpty()
                ) {

                    excludedDomains.addAll(
                        domains.second
                    )
                }

                continue
            }

            /*
             * denyallow.
             */
            if (
                option.startsWith(
                    "denyallow="
                )
            ) {

                val domains =
                    parseSimpleDomainList(
                        option.substring(
                            "denyallow=".length
                        )
                    )

                excludedDomains.addAll(
                    domains
                )

                continue
            }

            /*
             * Third-party only.
             */
            if (
                option == "third-party"
            ) {

                domainType =
                    DomainType.THIRD_PARTY

                continue
            }

            /*
             * First-party only.
             */
            if (
                option == "~third-party"
            ) {

                domainType =
                    DomainType.FIRST_PARTY

                continue
            }

            /*
             * Important rules get higher priority.
             */
            if (
                option == "important"
            ) {

                important = true

                priority = 100

                continue
            }

            /*
             * Unsupported browser actions.
             *
             * We skip the entire rule rather than accidentally
             * interpreting it as a normal block rule.
             */
            if (
                isUnsupportedAction(option)
            ) {
                return null
            }

            /*
             * Options that don't change DNS blocking behavior
             * are intentionally ignored.
             */
        }

        return ParsedOptions(
            positiveResourceTypes =
                positiveTypes,

            excludedResourceTypes =
                excludedTypes,

            includedDomains =
                includedDomains,

            excludedDomains =
                excludedDomains,

            domainType =
                domainType,

            priority =
                priority,

            important =
                important
        )
    }

    private fun parseDomainList(
        value: String
    ): Pair<List<String>, List<String>> {

        val included =
            ArrayList<String>()

        val excluded =
            ArrayList<String>()

        for (
            rawDomain in value.split('|')
        ) {

            val domain =
                rawDomain.trim()

            if (domain.isEmpty()) {
                continue
            }

            val isExcluded =
                domain.startsWith("~")

            val normalized =
                normalizeDomain(
                    if (isExcluded) {
                        domain.substring(1)
                    } else {
                        domain
                    }
                )

            if (normalized.isEmpty()) {
                continue
            }

            if (isExcluded) {
                excluded.add(normalized)
            } else {
                included.add(normalized)
            }
        }

        return included to excluded
    }

    private fun parseSimpleDomainList(
        value: String
    ): List<String> {

        return value
            .split('|')
            .mapNotNull {
                normalizeDomain(it)
                    .takeIf { domain ->
                        domain.isNotEmpty()
                    }
            }
    }

    private fun normalizeDomain(
        value: String
    ): String {

        var domain =
            value
                .trim()
                .lowercase()

        if (
            domain.startsWith("~")
        ) {
            domain =
                domain.substring(1)
        }

        domain =
            domain.trim('.')

        /*
         * ABP domain names must not contain URL
         * components.
         */
        if (
            domain.isEmpty() ||
            domain.contains("/") ||
            domain.contains(":") ||
            domain.any { it.isWhitespace() }
        ) {
            return ""
        }

        return domain
    }

    private fun resourceTypeFor(
        option: String
    ): ResourceType? {

        return when (
            option.lowercase()
        ) {

            "script" ->
                ResourceType.SCRIPT

            "image" ->
                ResourceType.IMAGE

            "stylesheet" ->
                ResourceType.STYLESHEET

            "font" ->
                ResourceType.FONT

            "media" ->
                ResourceType.MEDIA

            "object" ->
                ResourceType.OBJECT

            "xmlhttprequest" ->
                ResourceType.XMLHTTPREQUEST

            "xhr" ->
                ResourceType.XMLHTTPREQUEST

            "subdocument" ->
                ResourceType.SUB_FRAME

            "sub_frame" ->
                ResourceType.SUB_FRAME

            "ping" ->
                ResourceType.PING

            "websocket" ->
                ResourceType.WEBSOCKET

            "main_frame" ->
                ResourceType.MAIN_FRAME

            "document" ->
                ResourceType.MAIN_FRAME

            "other" ->
                ResourceType.OTHER

            else ->
                null
        }
    }

    private fun isUnsupportedAction(
        option: String
    ): Boolean {

        val lower =
            option.lowercase()

        return when {

            lower == "redirect" ->
                true

            lower.startsWith(
                "redirect="
            ) ->
                true

            lower == "redirect-rule" ->
                true

            lower.startsWith(
                "redirect-rule="
            ) ->
                true

            lower == "removeparam" ->
                true

            lower.startsWith(
                "removeparam="
            ) ->
                true

            lower == "csp" ->
                true

            lower.startsWith(
                "csp="
            ) ->
                true

            lower == "permissions" ->
                true

            lower.startsWith(
                "permissions="
            ) ->
                true

            lower == "replace" ->
                true

            lower.startsWith(
                "replace="
            ) ->
                true

            else ->
                false
        }
    }

    private data class ParsedOptions(
        val positiveResourceTypes:
            Set<ResourceType> =
            emptySet(),

        val excludedResourceTypes:
            Set<ResourceType> =
            emptySet(),

        val includedDomains:
            Set<String> =
            emptySet(),

        val excludedDomains:
            Set<String> =
            emptySet(),

        val domainType:
            DomainType =
            DomainType.ANY,

        val priority:
            Int = 1,

        val important:
            Boolean = false
    )

    companion object {

        const val DEFAULT_MAX_RULES =
            30_000
    }
}

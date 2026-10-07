package com.sathishkumarvasa.adblocker

enum class ResourceType {
    MAIN_FRAME,
    SUB_FRAME,
    SCRIPT,
    IMAGE,
    STYLESHEET,
    FONT,
    OBJECT,
    XMLHTTPREQUEST,
    PING,
    MEDIA,
    WEBSOCKET,
    OTHER
}

enum class DomainType {
    ANY,
    FIRST_PARTY,
    THIRD_PARTY
}

data class FilterRule(
    val pattern: String,
    val resourceTypes: Set<ResourceType> =
        ResourceType.entries.toSet(),
    val includedDomains: Set<String> =
        emptySet(),
    val excludedDomains: Set<String> =
        emptySet(),
    val domainType: DomainType =
        DomainType.ANY,
    val priority: Int = 1,
    val important: Boolean = false,
    val source: String = "unknown"
) {

    fun normalizedPattern(): String {
        return pattern.trim()
    }

    fun appliesToResource(
        resourceType: ResourceType
    ): Boolean {
        return resourceTypes.contains(
            resourceType
        )
    }

    fun appliesToDomain(
        domain: String
    ): Boolean {

        val normalized =
            normalizeDomain(domain)

        if (normalized.isEmpty()) {
            return false
        }

        if (
            excludedDomains.any {
                domainMatches(
                    normalized,
                    it
                )
            }
        ) {
            return false
        }

        if (
            includedDomains.isNotEmpty() &&
            includedDomains.none {
                domainMatches(
                    normalized,
                    it
                )
            }
        ) {
            return false
        }

        return true
    }

    private fun domainMatches(
        domain: String,
        ruleDomain: String
    ): Boolean {

        val normalizedRule =
            normalizeDomain(ruleDomain)

        return domain ==
            normalizedRule ||
            domain.endsWith(
                ".$normalizedRule"
            )
    }

    private fun normalizeDomain(
        domain: String
    ): String {

        return domain
            .trim()
            .lowercase()
            .trim('.')
    }
}

data class FilterSet(
    val rules: List<FilterRule>,
    val generatedAt: Long,
    val sourceLists: List<String>
) {

    val size: Int
        get() = rules.size
}

data class FilterUpdateResult(
    val success: Boolean,
    val ruleCount: Int = 0,
    val message: String = ""
)


package com.sathishkumarvasa.adblocker

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

class FilterRepository(
    private val context: Context,
    private val preferences: AppPreferences
) {

    companion object {

        const val EASY_LIST_URL =
            "https://easylist.to/easylist/easylist.txt"

        const val EASY_PRIVACY_URL =
            "https://easylist.to/easylist/easyprivacy.txt"

        const val MAX_RULES =
            30_000

        const val SEED_RULE_START =
            50_000
    }

    private val parser =
        AdblockParser(
            maxRules = MAX_RULES
        )

    suspend fun updateFilters(
        force: Boolean = false
    ): FilterUpdateResult =
        withContext(Dispatchers.IO) {

            if (!preferences.enabled.value) {

                preferences.setRuleCount(0)

                return@withContext FilterUpdateResult(
                    success = true,
                    ruleCount = 0,
                    message =
                        "Protection is disabled."
                )
            }

            val allRules =
                ArrayList<FilterRule>()

            /*
             * Seed rules from the original extension.
             */
            allRules.addAll(
                seedRules()
            )

            var successfulDownloads =
                0

            /*
             * EasyList.
             */
            val easyList =
                downloadText(
                    EASY_LIST_URL
                )

            if (easyList.isNotEmpty()) {

                successfulDownloads++

                allRules.addAll(
                    parser.parse(
                        easyList,
                        source = "EasyList"
                    )
                )
            }

            /*
             * EasyPrivacy.
             */
            if (
                allRules.size < MAX_RULES
            ) {

                val easyPrivacy =
                    downloadText(
                        EASY_PRIVACY_URL
                    )

                if (
                    easyPrivacy.isNotEmpty()
                ) {

                    successfulDownloads++

                    allRules.addAll(
                        parser.parse(
                            easyPrivacy,
                            source = "EasyPrivacy"
                        )
                    )
                }
            }

            /*
             * Custom rules.
             */
            if (
                allRules.size < MAX_RULES
            ) {

                for (
                    customRule
                    in preferences.customRules.value
                ) {

                    val parsed =
                        parser.parseLine(
                            customRule,
                            source = "Custom"
                        )

                    if (parsed != null) {
                        allRules.add(parsed)
                    }

                    if (
                        allRules.size >=
                        MAX_RULES
                    ) {
                        break
                    }
                }
            }

            /*
             * If all remote downloads failed and
             * there are no seed/custom rules, do
             * not destroy the existing filter set.
             */
            if (
                successfulDownloads == 0 &&
                allRules.isEmpty()
            ) {

                return@withContext FilterUpdateResult(
                    success = false,
                    ruleCount =
                        preferences.ruleCount.value,
                    message =
                        "Filter download failed."
                )
            }

            val uniqueRules =
                deduplicate(
                    allRules
                )

            val limitedRules =
                uniqueRules.take(
                    MAX_RULES
                )

            saveRules(
                limitedRules
            )

            preferences.setRuleCount(
                limitedRules.size
            )

            preferences.setLastUpdate(
                System.currentTimeMillis()
            )

            FilterUpdateResult(
                success = true,
                ruleCount =
                    limitedRules.size,
                message =
                    "Filters updated."
            )
        }

    private fun downloadText(
        address: String
    ): String {

        var connection:
            HttpURLConnection? = null

        return try {

            val url =
                URL(address)

            connection =
                url.openConnection()
                    as HttpURLConnection

            connection.requestMethod =
                "GET"

            connection.connectTimeout =
                20_000

            connection.readTimeout =
                30_000

            connection.useCaches =
                false

            connection.setRequestProperty(
                "Cache-Control",
                "no-cache"
            )

            connection.setRequestProperty(
                "User-Agent",
                "SathishKumarVasaAdBlocker/1.0"
            )

            val responseCode =
                connection.responseCode

            if (
                responseCode !in
                200..299
            ) {
                return ""
            }

            connection
                .inputStream
                .bufferedReader()
                .use {
                    it.readText()
                }

        } catch (
            _: Exception
        ) {

            ""

        } finally {

            connection?.disconnect()
        }
    }

    private fun deduplicate(
        rules: List<FilterRule>
    ): List<FilterRule> {

        val unique =
            LinkedHashMap<String, FilterRule>()

        for (rule in rules) {

            val key =
                buildString {

                    append(
                        rule.pattern
                    )

                    append('|')

                    append(
                        rule.resourceTypes
                            .sortedBy {
                                it.name
                            }
                            .joinToString(",")
                    )

                    append('|')

                    append(
                        rule.includedDomains
                            .sorted()
                            .joinToString(",")
                    )

                    append('|')

                    append(
                        rule.excludedDomains
                            .sorted()
                            .joinToString(",")
                    )

                    append('|')

                    append(
                        rule.domainType.name
                    )

                    append('|')

                    append(
                        rule.priority
                    )
                }

            if (
                !unique.containsKey(key)
            ) {
                unique[key] = rule
            }
        }

        return unique.values.toList()
    }

    private fun seedRules(): List<FilterRule> {

        val rules =
            mutableListOf<FilterRule>()

        fun add(
            pattern: String,
            resourceTypes:
                Set<ResourceType> =
                ResourceType.entries.toSet()
        ) {

            rules.add(
                FilterRule(
                    pattern = pattern,
                    resourceTypes =
                        resourceTypes,
                    priority = 10,
                    source = "Seed"
                )
            )
        }

        add(
            "||doubleclick.net^"
        )

        add(
            "||googlesyndication.com^"
        )

        add(
            "||googleadservices.com^"
        )

        add(
            "||googleads.g.doubleclick.net^"
        )

        add(
            "||pagead2.googlesyndication.com^"
        )

        add(
            "||adservice.google.com^"
        )

        add(
            "||adnxs.com^"
        )

        add(
            "||adsrvr.org^"
        )

        add(
            "||adform.net^"
        )

        add(
            "||criteo.com^"
        )

        add(
            "||taboola.com^"
        )

        add(
            "||outbrain.com^"
        )

        add(
            "||amazon-adsystem.com^"
        )

        add(
            "||2mdn.net^"
        )

        add(
            "||googletagservices.com^"
        )

        add(
            "||3lift.com^"
        )

        add(
            "||rubiconproject.com^"
        )

        add(
            "||pubmatic.com^"
        )

        add(
            "||openx.net^"
        )

        return rules
    }

    private fun saveRules(
        rules: List<FilterRule>
    ) {

        val preferences =
            context.getSharedPreferences(
                "filter_rules",
                Context.MODE_PRIVATE
            )

        val serialized =
            rules.map {
                serializeRule(it)
            }

        preferences
            .edit()
            .putStringSet(
                "rules",
                serialized.toSet()
            )
            .putLong(
                "saved_at",
                System.currentTimeMillis()
            )
            .apply()
    }

    fun loadRules(): List<FilterRule> {

        val preferences =
            context.getSharedPreferences(
                "filter_rules",
                Context.MODE_PRIVATE
            )

        val serialized =
            preferences.getStringSet(
                "rules",
                emptySet()
            )
                ?: emptySet()

        return serialized.mapNotNull {
            deserializeRule(it)
        }
    }

    private fun serializeRule(
        rule: FilterRule
    ): String {

        return listOf(
            rule.pattern,
            rule.resourceTypes
                .joinToString(",") {
                    it.name
                },
            rule.includedDomains
                .joinToString(","),
            rule.excludedDomains
                .joinToString(","),
            rule.domainType.name,
            rule.priority.toString(),
            rule.important.toString(),
            rule.source
        ).joinToString(
            "\u001F"
        )
    }

    private fun deserializeRule(
        value: String
    ): FilterRule? {

        return try {

            val fields =
                value.split(
                    "\u001F"
                )

            if (fields.size < 8) {
                return null
            }

            val resourceTypes =
                fields[1]
                    .split(',')
                    .mapNotNull {
                        runCatching {
                            ResourceType.valueOf(it)
                        }.getOrNull()
                    }
                    .toSet()

            val includedDomains =
                fields[2]
                    .split(',')
                    .filter {
                        it.isNotBlank()
                    }
                    .toSet()

            val excludedDomains =
                fields[3]
                    .split(',')
                    .filter {
                        it.isNotBlank()
                    }
                    .toSet()

            FilterRule(
                pattern =
                    fields[0],

                resourceTypes =
                    resourceTypes,

                includedDomains =
                    includedDomains,

                excludedDomains =
                    excludedDomains,

                domainType =
                    runCatching {
                        DomainType.valueOf(
                            fields[4]
                        )
                    }.getOrDefault(
                        DomainType.ANY
                    ),

                priority =
                    fields[5].toIntOrNull()
                        ?: 1,

                important =
                    fields[6].toBoolean(),

                source =
                    fields[7]
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }
}


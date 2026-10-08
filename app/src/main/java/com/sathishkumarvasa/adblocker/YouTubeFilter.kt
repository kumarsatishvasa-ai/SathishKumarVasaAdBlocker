package com.sathishkumarvasa.adblocker

import android.util.Log
import java.util.Locale

/**
 * YouTube-specific traffic classifier.
 *
 * IMPORTANT:
 * This class does NOT block YouTube traffic.
 *
 * YouTube uses shared infrastructure for:
 * - video playback
 * - thumbnails
 * - metadata
 * - comments
 * - authentication
 * - advertisements
 *
 * Blocking broad YouTube infrastructure such as
 * googlevideo.com can break video playback.
 *
 * This class only identifies YouTube-related hostnames.
 */
object YouTubeFilter {

    private const val TAG = "YouTubeFilter"

    /**
     * Domains associated with normal YouTube infrastructure.
     *
     * Classification only.
     * These domains must NOT automatically be blocked.
     */
    private val YOUTUBE_SUFFIXES = setOf(
        "youtube.com",
        "youtube-nocookie.com",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com"
    )

    /**
     * Main YouTube application hosts.
     */
    private val YOUTUBE_SERVICE_HOSTS = setOf(
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "youtu.be",
        "www.youtu.be",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com"
    )

    /**
     * Returns true when the hostname belongs to
     * YouTube-related infrastructure.
     */
    fun isYouTubeHost(
        hostname: String
    ): Boolean {

        val host = normalize(hostname)
            ?: return false

        if (YOUTUBE_SERVICE_HOSTS.contains(host)) {
            return true
        }

        for (suffix in YOUTUBE_SUFFIXES) {
            if (
                host == suffix ||
                host.endsWith(".$suffix")
            ) {
                return true
            }
        }

        return false
    }

    /**
     * Returns true for YouTube media infrastructure.
     *
     * googlevideo.com is used for media delivery.
     *
     * NEVER block this automatically.
     */
    fun isYouTubeMediaHost(
        hostname: String
    ): Boolean {

        val host = normalize(hostname)
            ?: return false

        return host == "googlevideo.com" ||
            host.endsWith(".googlevideo.com")
    }

    /**
     * Returns true for normal YouTube application hosts.
     */
    fun isYouTubeApplicationHost(
        hostname: String
    ): Boolean {

        val host = normalize(hostname)
            ?: return false

        return host == "youtube.com" ||
            host.endsWith(".youtube.com") ||
            host == "youtube-nocookie.com" ||
            host.endsWith(".youtube-nocookie.com")
    }

    /**
     * Returns true for YouTube image and thumbnail infrastructure.
     *
     * These hosts should NOT be blocked.
     */
    fun isYouTubeImageHost(
        hostname: String
    ): Boolean {

        val host = normalize(hostname)
            ?: return false

        return host == "ytimg.com" ||
            host.endsWith(".ytimg.com") ||
            host == "ggpht.com" ||
            host.endsWith(".ggpht.com")
    }

    /**
     * Safe DNS decision function.
     *
     * YouTube traffic is always allowed.
     *
     * Ordinary DNS blocking remains the responsibility
     * of FilterManager.
     */
    fun shouldBlockDnsHost(
        hostname: String
    ): Boolean {

        val host = normalize(hostname)
            ?: return false

        if (isYouTubeHost(host)) {
            Log.d(
                TAG,
                "Allowing YouTube infrastructure: $host"
            )

            return false
        }

        /*
         * This class is not an independent blocklist.
         *
         * Return false for all non-YouTube hosts as well.
         */
        return false
    }

    /**
     * Classifies a hostname.
     */
    fun classify(
        hostname: String
    ): TrafficType {

        val host = normalize(hostname)
            ?: return TrafficType.OTHER

        return when {

            isYouTubeMediaHost(host) ->
                TrafficType.YOUTUBE_MEDIA

            isYouTubeImageHost(host) ->
                TrafficType.YOUTUBE_IMAGE

            isYouTubeApplicationHost(host) ->
                TrafficType.YOUTUBE_APPLICATION

            isYouTubeHost(host) ->
                TrafficType.YOUTUBE_SERVICE

            else ->
                TrafficType.OTHER
        }
    }

    /**
     * Describes the detected hostname type.
     */
    enum class TrafficType {

        YOUTUBE_APPLICATION,

        YOUTUBE_MEDIA,

        YOUTUBE_IMAGE,

        YOUTUBE_SERVICE,

        OTHER
    }

    /**
     * Normalize a plain hostname.
     *
     * This method intentionally does not interpret URLs,
     * paths, query strings, or filter syntax.
     */
    private fun normalize(
        hostname: String
    ): String? {

        var value = hostname
            .trim()
            .lowercase(Locale.US)

        if (value.isEmpty()) {
            return null
        }

        /*
         * Remove an accidental trailing DNS dot.
         */
        value = value.trim('.')

        if (value.isEmpty()) {
            return null
        }

        /*
         * Reject values that are not plain hostnames.
         */
        if (
            value.contains("/") ||
            value.contains("?") ||
            value.contains("#") ||
            value.contains(" ") ||
            value.contains("|") ||
            value.contains("^") ||
            value.contains(":")
        ) {
            return null
        }

        /*
         * Avoid treating IPv4 addresses as hostnames.
         */
        if (isIpv4(value)) {
            return null
        }

        return value
    }

    /**
     * Conservative IPv4 check.
     */
    private fun isIpv4(
        value: String
    ): Boolean {

        val parts = value.split(".")

        if (parts.size != 4) {
            return false
        }

        for (part in parts) {

            if (part.isEmpty()) {
                return false
            }

            val number =
                part.toIntOrNull()
                    ?: return false

            if (number !in 0..255) {
                return false
            }
        }

        return true
    }
}

package com.sathishkumarvasa.adblocker

import android.util.Log
import java.util.Locale

/**

YouTube-specific traffic classifier.

IMPORTANT:

This class intentionally DOES NOT block YouTube domains.

YouTube uses shared infrastructure for:

video playback

thumbnails

metadata

comments

authentication

advertisements

Blocking googlevideo.com or broad YouTube infrastructure at

the DNS/VPN layer can therefore break playback.

This class safely identifies YouTube-related hostnames so a

future application/content-level component can make a more

informed decision.
*/
object YouTubeFilter {

private const val TAG =
"YouTubeFilter"

/**

Domains associated with normal YouTube operation.

These are classification domains only.

They MUST NOT automatically be blocked.
*/
private val YOUTUBE_SUFFIXES =
setOf(
"youtube.com",
"youtube-nocookie.com",
"googlevideo.com",
"ytimg.com",
"ggpht.com"
)

/**

Hostnames that are commonly associated with YouTube

application services.

Again, these are classification entries, NOT block rules.
*/
private val YOUTUBE_SERVICE_HOSTS =
setOf(
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

Returns true when the hostname belongs to YouTube's

normal infrastructure.
*/
fun isYouTubeHost(
hostname: String
): Boolean {

val host =
normalize(hostname)
?: return false

if (
YOUTUBE_SERVICE_HOSTS.contains(host)
) {
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

Returns true for YouTube media infrastructure.

This is intentionally informational only.

The caller must NOT block these hosts merely because

this method returns true.
*/
fun isYouTubeMediaHost(
hostname: String
): Boolean {

val host =
normalize(hostname)
?: return false

/*

googlevideo.com is used for video/media delivery.

Blocking it is likely to break playback.
*/
return host == "googlevideo.com" ||
host.endsWith(
".googlevideo.com"
)
}

/**

Returns true for normal YouTube web/application hosts.
*/
fun isYouTubeApplicationHost(
hostname: String
): Boolean {

val host =
normalize(hostname)
?: return false

return host == "youtube.com" ||
host.endsWith(".youtube.com") ||
host == "youtube-nocookie.com" ||
host.endsWith(".youtube-nocookie.com")
}

/**

Returns true for YouTube image/thumbnail infrastructure.

These hosts should NOT be blocked.
*/
fun isYouTubeImageHost(
hostname: String
): Boolean {

val host =
normalize(hostname)
?: return false

return host == "ytimg.com" ||
host.endsWith(".ytimg.com") ||
host == "ggpht.com" ||
host.endsWith(".ggpht.com")
}

/**

Safe decision function for integration with the VPN.

It ALWAYS returns false for YouTube hosts.

This is deliberate:

YouTube-specific DNS blocking is not reliable enough to

distinguish advertisement traffic from video traffic.
*/
fun shouldBlockDnsHost(
hostname: String
): Boolean {

val host =
normalize(hostname)
?: return false

if (
isYouTubeHost(host)
) {

 Log.d(
     TAG,
     "Allowing YouTube infrastructure: $host"
 )

 return false


}

/*

Do not make this method a second ad-block database.

Ordinary DNS filtering remains the responsibility of

FilterManager.
*/
return false
}

/**

Central classification helper.
*/
fun classify(
hostname: String
): TrafficType {

val host =
normalize(hostname)
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

Describes the type of hostname detected.
*/
enum class TrafficType {

YOUTUBE_APPLICATION,

YOUTUBE_MEDIA,

YOUTUBE_IMAGE,

YOUTUBE_SERVICE,

OTHER
}

/**

Normalizes a hostname without attempting to interpret

URLs, paths, query strings, or filter syntax.
*/
private fun normalize(
hostname: String
): String? {

var value =
hostname
.trim()
.lowercase(Locale.US)

if (
value.isEmpty()
) {
return null
}

/*

Remove an accidental trailing dot.
*/
value =
value.trim('.')

/*

Reject things that are not plain hostnames.
/
if (
value.contains("/") ||
value.contains("?") ||
value.contains("#") ||
value.contains(" ") ||
value.contains("") ||
value.contains("|") ||
value.contains("^")
) {
return null
}

/*

Avoid accidentally treating an IPv4 address as

a YouTube hostname.
*/
if (
isIpv4(value)
) {
return null
}

return value
}

private fun isIpv4(
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
}

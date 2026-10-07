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

    /*
     * Allowlist takes priority over blocklist.
     */
    val allowlist =
        AdBlockStorage.getAllowlist(context)

    var current =
        normalized

    while (true) {

        if (allowlist.contains(current)) {
            return false
        }

        val dot =
            current.indexOf('.')

        if (dot < 0) {
            break
        }

        current =
            current.substring(
                dot + 1
            )
    }

    /*
     * Exact hostname.
     */
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
     * can match example.com
     */
    current =
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

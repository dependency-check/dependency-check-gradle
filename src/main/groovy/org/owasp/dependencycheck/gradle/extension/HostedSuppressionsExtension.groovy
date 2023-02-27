package org.owasp.dependencycheck.gradle.extension

/**
 * The advanced configuration for the hosted suppressions file.
 */
class HostedSuppressionsExtension {
    /**
     * Whether the hosted suppressions fie will be used.
     */
    Boolean enabled
    /**
     * The URL for a mirrored hosted suppressions file.
     */
    String url
    /**
     * Whether the hosted suppressions file should be updated regardless of the `autoupdate` setting.
     */
    Boolean forceupdate
    /**
     * The number of hours to wait before checking for changes in the hosted suppressions file.
     */
    Integer validForHours
}

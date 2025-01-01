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
     * Credentials used for basic authentication for a mirrored hosted suppressions file.
     */
    String user
    /**
     * Credentials used for basic authentication for a mirrored hosted suppressions file.
     */
    String password
    /**
     * Credentials used for bearer authentication for a mirrored hosted suppressions file.
     */
    String bearerToken
    /**
     * Whether the hosted suppressions file should be updated regardless of the `autoupdate` setting.
     */
    Boolean forceupdate
    /**
     * The number of hours to wait before checking for changes in the hosted suppressions file.
     */
    Integer validForHours
}

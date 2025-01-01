package org.owasp.dependencycheck.gradle.extension

class KEVExtension {
    /**
     * Sets whether the Known Exploited Vulnerability update and Analyzer will be used.
     */
    Boolean enabled
    /**
     * URL to the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    String url
    /**
     * Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    String user
    /**
     * Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    String password
    /**
     * Credentials used for bearer authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    String bearerToken
    /**
     * Controls the skipping of the check for Known Exploited Vulnerabilities updates.
     */
    Integer validForHours
}

package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

@groovy.transform.CompileStatic
class KEVExtension {

    private final Property<Boolean> enabled
    private final Property<String> url
    private final Property<String> user
    private final Property<String> password
    private final Property<String> bearerToken
    private final Property<Integer> validForHours

    @Inject
    KEVExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.url = objects.property(String)
        this.user = objects.property(String)
        this.password = objects.property(String)
        this.bearerToken = objects.property(String)
        this.validForHours = objects.property(Integer)
    }

    /**
     * Sets whether the Known Exploited Vulnerability update and Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getEnabled() {
        return enabled
    }

    void setEnabled(Boolean value) {
        enabled.set(value)
    }

    /**
     * URL to the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    @Input
    @Optional
    Property<String> getUrl() {
        return url
    }

    void setUrl(String value) {
        url.set(value)
    }

    /**
     * Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    @Input
    @Optional
    Property<String> getUser() {
        return user
    }

    void setUser(String value) {
        user.set(value)
    }

    /**
     * Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    @Input
    @Optional
    Property<String> getPassword() {
        return password
    }

    void setPassword(String value) {
        password.set(value)
    }

    /**
     * Credentials used for bearer authentication for the CISA Known Exploited Vulnerabilities JSON data feed.
     */
    @Input
    @Optional
    Property<String> getBearerToken() {
        return bearerToken
    }

    void setBearerToken(String value) {
        bearerToken.set(value)
    }

    /**
     * Controls the skipping of the check for Known Exploited Vulnerabilities updates.
     */
    @Input
    @Optional
    Property<Integer> getValidForHours() {
        return validForHours
    }

    void setValidForHours(Integer value) {
        validForHours.set(value)
    }
}

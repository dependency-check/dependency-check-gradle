package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The advanced configuration for the hosted suppressions file.
 */
@groovy.transform.CompileStatic
class HostedSuppressionsExtension {

    private final Property<Boolean> enabled
    private final Property<String> url
    private final Property<String> user
    private final Property<String> password
    private final Property<String> bearerToken
    private final Property<Boolean> forceupdate
    private final Property<Integer> validForHours

    @Inject
    HostedSuppressionsExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.url = objects.property(String)
        this.user = objects.property(String)
        this.password = objects.property(String)
        this.bearerToken = objects.property(String)
        this.forceupdate = objects.property(Boolean)
        this.validForHours = objects.property(Integer)
    }

    /**
     * Whether the hosted suppressions fie will be used.
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
     * The URL for a mirrored hosted suppressions file.
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
     * Credentials used for basic authentication for a mirrored hosted suppressions file.
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
     * Credentials used for basic authentication for a mirrored hosted suppressions file.
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
     * Credentials used for bearer authentication for a mirrored hosted suppressions file.
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
     * Whether the hosted suppressions file should be updated regardless of the `autoupdate` setting.
     */
    @Input
    @Optional
    Property<Boolean> getForceupdate() {
        return forceupdate
    }

    void setForceupdate(Boolean value) {
        forceupdate.set(value)
    }

    /**
     * The number of hours to wait before checking for changes in the hosted suppressions file.
     */
    @Input
    @Optional
    Property<Integer> getValidForHours() {
        return validForHours
    }

    void setValidForHours(Number value) {
        validForHours.set(value?.intValue())
    }
}

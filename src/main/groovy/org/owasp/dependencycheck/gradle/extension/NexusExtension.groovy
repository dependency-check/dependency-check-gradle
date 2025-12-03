package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

/**
 * Nexus analyzer configuration.
 */
interface NexusExtension {

    /**
     * Sets whether the Nexus Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getEnabled()

    /**
     * Nexus server URL.
     */
    @Input
    @Optional
    Property<String> getUrl()

    /**
     * Whether Nexus should be accessed through a proxy.
     */
    @Input
    @Optional
    Property<Boolean> getUsesProxy()

    /**
     * Nexus basic auth username.
     */
    @Input
    @Optional
    Property<String> getUsername()

    /**
     * Nexus basic auth password.
     */
    @Input
    @Optional
    Property<String> getPassword()

}

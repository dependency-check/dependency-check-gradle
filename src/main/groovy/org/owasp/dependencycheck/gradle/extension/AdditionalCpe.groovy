package org.owasp.dependencycheck.gradle.extension

import groovy.transform.CompileStatic
import org.gradle.api.Named
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * Holder for the information regarding an additional CPE to be checked.
 */
@CompileStatic
abstract class AdditionalCpe implements Named {

    @Inject abstract ObjectFactory getObjects()

    private final String name
    private final Property<String> description
    private final Property<String> cpe

    AdditionalCpe(String name) {
        this.name = name
        this.description = objects.property(String)
        this.cpe = objects.property(String)
    }

    /**
     * Name assigned to the CPE entry during configuration.
     */
    @Override
    String getName() {
        return name
    }

    /**
     * Description for the what the CPE represents.
     */
    @Input
    @Optional
    Property<String> getDescription() {
        return description
    }

    void setDescription(String value) {
        description.set(value)
    }

    /**
     * The CPE to be checked against the database.
     */
    @Input
    @Optional
    Property<String> getCpe() {
        return cpe
    }

    void setCpe(String value) {
        cpe.set(value)
    }
}

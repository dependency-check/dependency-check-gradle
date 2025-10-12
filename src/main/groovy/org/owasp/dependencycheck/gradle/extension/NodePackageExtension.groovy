/*
 * This file is part of dependency-check-gradle.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The configuration for the Node Package Analyzer.
 */
@groovy.transform.CompileStatic
class NodePackageExtension {

    private final Property<Boolean> enabled
    private final Property<Boolean> skipDevDependencies

    @Inject
    NodePackageExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.skipDevDependencies = objects.property(Boolean)
    }

    /**
     * Sets whether the Node Package Analyzer should be used.
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
     * Sets whether the Node Package Analyzer should skip devDependencies.
     */
    @Input
    @Optional
    Property<Boolean> getSkipDevDependencies() {
        return skipDevDependencies
    }

    void setSkipDevDependencies(Boolean value) {
        skipDevDependencies.set(value)
    }
}

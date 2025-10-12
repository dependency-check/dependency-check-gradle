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
 * The configuration for the Node Audit Analyzer.
 */
@groovy.transform.CompileStatic
class NodeAuditExtension {

    private final Property<Boolean> enabled
    private final Property<Boolean> useCache
    private final Property<Boolean> skipDevDependencies
    private final Property<Boolean> yarnEnabled
    private final Property<String> yarnPath
    private final Property<Boolean> pnpmEnabled
    private final Property<String> pnpmPath
    private final Property<String> url

    @Inject
    NodeAuditExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.useCache = objects.property(Boolean)
        this.skipDevDependencies = objects.property(Boolean)
        this.yarnEnabled = objects.property(Boolean)
        this.yarnPath = objects.property(String)
        this.pnpmEnabled = objects.property(Boolean)
        this.pnpmPath = objects.property(String)
        this.url = objects.property(String)
    }

    /**
     * Sets whether the Node Audit Analyzer should be used.
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
     * Sets whether the Node Audit Analyzer should cache results locally.
     */
    @Input
    @Optional
    Property<Boolean> getUseCache() {
        return useCache
    }

    void setUseCache(Boolean value) {
        useCache.set(value)
    }

    /**
     * Sets whether the Node Audit Analyzer should skip devDependencies.
     */
    @Input
    @Optional
    Property<Boolean> getSkipDevDependencies() {
        return skipDevDependencies
    }

    void setSkipDevDependencies(Boolean value) {
        skipDevDependencies.set(value)
    }

    /**
     * Sets whether the Yarn Audit Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getYarnEnabled() {
        return yarnEnabled
    }

    void setYarnEnabled(Boolean value) {
        yarnEnabled.set(value)
    }

    /**
     * The path to `yarn`.
     */
    @Input
    @Optional
    Property<String> getYarnPath() {
        return yarnPath
    }

    void setYarnPath(String value) {
        yarnPath.set(value)
    }

    /**
     * Sets whether the Pnpm Audit Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getPnpmEnabled() {
        return pnpmEnabled
    }

    void setPnpmEnabled(Boolean value) {
        pnpmEnabled.set(value)
    }

    /**
     * The path to `pnpm`.
     */
    @Input
    @Optional
    Property<String> getPnpmPath() {
        return pnpmPath
    }

    void setPnpmPath(String value) {
        pnpmPath.set(value)
    }

    /**
     * The URL to the NPM Audit API.
     */
    @Input
    @Optional
    Property<String> getUrl() {
        return url
    }

    void setUrl(String value) {
        url.set(value)
    }
}

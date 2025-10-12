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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The configuration for the RetireJS Analyzer.
 */
@groovy.transform.CompileStatic
class RetireJSExtension {

    private final Property<Boolean> enabled
    private final ListProperty<String> filters
    private final Property<Boolean> filterNonVulnerable
    private final Property<String> retireJsUrl
    private final Property<String> user
    private final Property<String> password
    private final Property<String> bearerToken
    private final Property<Boolean> forceupdate

    @Inject
    RetireJSExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.filters = objects.listProperty(String).empty()
        this.filterNonVulnerable = objects.property(Boolean)
        this.retireJsUrl = objects.property(String)
        this.user = objects.property(String)
        this.password = objects.property(String)
        this.bearerToken = objects.property(String)
        this.forceupdate = objects.property(Boolean)
    }

    /**
     * Sets whether the RetireJS Analyzer should be used.
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
     * The JS content filters (regular expressions) used to filter which JS files will be skipped if the content matches one
     * of the filters. This is most commonly used to filter by copyright.
     */
    @Input
    @Optional
    ListProperty<String> getFilters() {
        return filters
    }

    void setFilters(List<String> value) {
        filters.set(value)
    }

    /**
     * Whether the Retire JS analyzer should filter the non-vunerable JS from the report.
     */
    @Input
    @Optional
    Property<Boolean> getFilterNonVulnerable() {
        return filterNonVulnerable
    }

    void setFilterNonVulnerable(Boolean value) {
        filterNonVulnerable.set(value)
    }

    /**
     * The Retire JS Repository URL.
     */
    @Input
    @Optional
    Property<String> getRetireJsUrl() {
        return retireJsUrl
    }

    void setRetireJsUrl(String value) {
        retireJsUrl.set(value)
    }

    /**
     * Credentials used for basic authentication for the Retire JS Repository URL.
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
     * Credentials used for basic authentication for the Retire JS Repository URL.
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
     * Credentials used for bearer authentication for the Retire JS Repository URL.
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
     * Whether the Retire JS analyzer should be updated regardless of the `autoupdate` setting.
     */
    @Input
    @Optional
    Property<Boolean> getForceupdate() {
        return forceupdate
    }

    void setForceupdate(Boolean value) {
        forceupdate.set(value)
    }
}

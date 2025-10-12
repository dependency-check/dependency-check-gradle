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
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The artifactory analyzer configuration.
 */
@groovy.transform.CompileStatic
class ArtifactoryExtension {

    private final Property<Boolean> enabled
    private final Property<String> url
    private final Property<Boolean> usesProxy
    private final Property<Boolean> parallelAnalysis
    private final Property<String> username
    private final Property<String> apiToken
    private final Property<String> bearerToken

    @Inject
    ArtifactoryExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.url = objects.property(String)
        this.usesProxy = objects.property(Boolean)
        this.parallelAnalysis = objects.property(Boolean)
        this.username = objects.property(String)
        this.apiToken = objects.property(String)
        this.bearerToken = objects.property(String)
    }

    /**
     * Sets whether the Artifactory Analyzer should be used.
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
     * The Artifactory server URL.
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
     * Whether Artifactory should be accessed through a proxy or not.
     */
    @Input
    @Optional
    Property<Boolean> getUsesProxy() {
        return usesProxy
    }

    void setUsesProxy(Boolean value) {
        usesProxy.set(value)
    }

    /**
     * Whether the Artifactory analyzer should be run in parallel or not.
     */
    @Input
    @Optional
    Property<Boolean> getParallelAnalysis() {
        return parallelAnalysis
    }

    void setParallelAnalysis(Boolean value) {
        parallelAnalysis.set(value)
    }

    /**
     * The user name (only used with API token) to connect to Artifactory instance.
     */
    @Input
    @Optional
    Property<String> getUsername() {
        return username
    }

    void setUsername(String value) {
        username.set(value)
    }

    /**
     * The API token to connect to Artifactory instance.
     */
    @Input
    @Optional
    Property<String> getApiToken() {
        return apiToken
    }

    void setApiToken(String value) {
        apiToken.set(value)
    }

    /**
     * The bearer token to connect to Artifactory instance.
     */
    @Input
    @Optional
    Property<String> getBearerToken() {
        return bearerToken
    }

    void setBearerToken(String value) {
        bearerToken.set(value)
    }
}

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
 * The configuration for the OSS Index Analyzer.
 */
@groovy.transform.CompileStatic
class OssIndexExtension {

    private final Property<Boolean> enabled
    private final Property<String> username
    private final Property<String> password
    private final Property<String> url
    private final Property<Boolean> warnOnlyOnRemoteErrors

    @Inject
    OssIndexExtension(ObjectFactory objects) {
        this.enabled = objects.property(Boolean)
        this.username = objects.property(String)
        this.password = objects.property(String)
        this.url = objects.property(String)
        this.warnOnlyOnRemoteErrors = objects.property(Boolean)
    }

    /**
     * Sets whether the OSS Index Analyzer should be used.
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
     * The optional username to connect to the OSS Index
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
     * The optional password or API token to connect to the OSS Index
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
     * The OSS Index URL.
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
     * Only output a warning message instead of failing when remote errors occur.
     */
    @Input
    @Optional
    Property<Boolean> getWarnOnlyOnRemoteErrors() {
        return warnOnlyOnRemoteErrors
    }

    void setWarnOnlyOnRemoteErrors(Boolean value) {
        warnOnlyOnRemoteErrors.set(value)
    }
}

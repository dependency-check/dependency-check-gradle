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
 * The configuration for caching external results.
 */
@groovy.transform.CompileStatic
class CacheExtension {

    private final Property<Boolean> ossIndex
    private final Property<Boolean> central
    private final Property<Boolean> nodeAudit

    @Inject
    CacheExtension(ObjectFactory objects) {
        this.ossIndex = objects.property(Boolean)
        this.central = objects.property(Boolean)
        this.nodeAudit = objects.property(Boolean)
    }

    /**
     * Sets whether the OSS Index Analyzer's results should be cached locally.
     * Cache expires after 24 hours.
     */
    @Input
    @Optional
    Property<Boolean> getOssIndex() {
        return ossIndex
    }

    void setOssIndex(Boolean value) {
        ossIndex.set(value)
    }

    /**
     * Sets whether the Central Analyzer's results should be cached locally.
     * Cache expires after 30 days.
     */
    @Input
    @Optional
    Property<Boolean> getCentral() {
        return central
    }

    void setCentral(Boolean value) {
        central.set(value)
    }

    /**
     * Sets whether the Node Audit Analyzer's results should be cached locally.
     * Cache expires after 24 hours.
     */
    @Input
    @Optional
    Property<Boolean> getNodeAudit() {
        return nodeAudit
    }

    void setNodeAudit(Boolean value) {
        nodeAudit.set(value)
    }
}

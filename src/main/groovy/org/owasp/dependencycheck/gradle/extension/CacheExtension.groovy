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

/**
 * The configuration for caching external results.
 */
@groovy.transform.CompileStatic
class CacheExtension {
    /**
     * Sets whether the OSS Index Analyzer's results should be cached locally.
     * Cache expires after 24 hours.
     */
    Boolean ossIndex
    /**
     * Sets whether the Central Analyzer's results should be cached locally.
     * Cache expires after 30 days.
     */
    Boolean central
    /**
     * Sets whether the Node Audit Analyzer's results should be cached locally.
     * Cache expires after 24 hours.
     */
    Boolean nodeAudit
}

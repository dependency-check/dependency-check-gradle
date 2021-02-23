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

/**
 * The configuration for the Node Audit Analyzer.
 */
class NodeAuditExtension {
    /**
     * Sets whether or not the Node Audit Analyzer should be used.
     */
    Boolean enabled
    /**
     * Sets whether or not the Node Audit Analyzer should cache results locally.
     */
    Boolean useCache
    /**
     * Sets whether or not the Node Audit Analyzer should skip devDependencies.
     */
    Boolean skipDevDependencies
    /**
     * Sets whether or not the Yarn Audit Analyzer should be used.
     */
    Boolean yarnEnabled
    /**
     * The path to `yarn`.
     */
    String yarnPath
}

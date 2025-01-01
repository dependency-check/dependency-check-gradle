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
 * The configuration for the RetireJS Analyzer.
 */
@groovy.transform.CompileStatic
class RetireJSExtension {
    /**
     * Sets whether the RetireJS Analyzer should be used.
     */
    Boolean enabled
    /**
     * The JS content filters (regular expressions) used to filter which JS files will be skipped if the content matches one
     * of the filters. This is most commonly used to filter by copyright.
     */
    List<String>  filters = []
    /**
     * Whether the Retire JS analyzer should filter the non-vunerable JS from the report.
     */
    Boolean filterNonVulnerable
    /**
     * The Retire JS Repository URL.
     */
    String retireJsUrl
    /**
     * Credentials used for basic authentication for the Retire JS Repository URL.
     */
    String user
    /**
     * Credentials used for basic authentication for the Retire JS Repository URL.
     */
    String password
    /**
     * Credentials used for bearer authentication for the Retire JS Repository URL.
     */
    String bearerToken
    /**
     * Whether the Retire JS analyzer should be updated regardless of the `autoupdate` setting.
     */
    Boolean forceupdate
}

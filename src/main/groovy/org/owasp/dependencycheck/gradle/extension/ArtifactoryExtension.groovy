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
 * The artifactory analyzer configuration.
 */
@groovy.transform.CompileStatic
class ArtifactoryExtension {
    /**
     * Sets whether the Artifactory Analyzer should be used.
     */
    Boolean enabled
    /**
     * The Artifactory server URL.
     */
    String url
    /**
     * Whether Artifactory should be accessed through a proxy or not.
     */
    Boolean usesProxy
    /**
     * Whether the Artifactory analyzer should be run in parallel or not.
     */
    Boolean parallelAnalysis
    /**
     * The user name (only used with API token) to connect to Artifactory instance.
     */
    String username
    /**
     * The API token to connect to Artifactory instance.
     */
    String apiToken
    /**
     * The bearer token to connect to Artifactory instance.
     */
    String bearerToken
}

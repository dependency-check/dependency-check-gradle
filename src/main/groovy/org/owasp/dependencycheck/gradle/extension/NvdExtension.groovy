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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.extension;

@groovy.transform.CompileStatic
class NvdExtension {
    /**
     * The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key.
     */
    String apiKey
    /**
     * The number of milliseconds to wait between calls to the NVD API.
     */
    Integer delay
    /**
     * The number records for a single page from NVD API (must be <=2000).
     */
    Integer resultsPerPage
    /**
     * The maximum number of retry requests for a single call to the NVD API.
     */
    Integer maxRetryCount
    /**
     * The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data.
     */
    String datafeedUrl
    /**
     * Credentials used for basic authentication for the NVD API Data feed.
     */
    String datafeedUser
    /**
     * Credentials used for basic authentication for the NVD API Data feed.
     */
    String datafeedPassword
    /**
     * The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.
     */
    Integer validForHours
    /**
     * The NVD API endpoint URL; configuring this is uncommon.
     */
    String endpoint;
}

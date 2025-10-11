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

package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

@groovy.transform.CompileStatic
class NvdExtension {

    private final Property<String> apiKey
    private final Property<Integer> delay
    private final Property<Integer> resultsPerPage
    private final Property<Integer> maxRetryCount
    private final Property<String> datafeedUrl
    private final Property<String> datafeedUser
    private final Property<String> datafeedPassword
    private final Property<String> datafeedBearerToken
    private final Property<Integer> datafeedStartYear
    private final Property<Integer> validForHours
    private final Property<String> endpoint

    @Inject
    NvdExtension(ObjectFactory objects) {
        this.apiKey = objects.property(String)
        this.delay = objects.property(Integer)
        this.resultsPerPage = objects.property(Integer)
        this.maxRetryCount = objects.property(Integer)
        this.datafeedUrl = objects.property(String)
        this.datafeedUser = objects.property(String)
        this.datafeedPassword = objects.property(String)
        this.datafeedBearerToken = objects.property(String)
        this.datafeedStartYear = objects.property(Integer)
        this.validForHours = objects.property(Integer)
        this.endpoint = objects.property(String)
    }

    /**
     * The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key.
     */
    @Input
    @Optional
    Property<String> getApiKey() {
        return apiKey
    }

    void setApiKey(String value) {
        apiKey.set(value)
    }

    /**
     * The number of milliseconds to wait between calls to the NVD API.
     */
    @Input
    @Optional
    Property<Integer> getDelay() {
        return delay
    }

    void setDelay(Integer value) {
        delay.set(value)
    }

    /**
     * The number records for a single page from NVD API (must be <=2000).
     */
    @Input
    @Optional
    Property<Integer> getResultsPerPage() {
        return resultsPerPage
    }

    void setResultsPerPage(Integer value) {
        resultsPerPage.set(value)
    }

    /**
     * The maximum number of retry requests for a single call to the NVD API.
     */
    @Input
    @Optional
    Property<Integer> getMaxRetryCount() {
        return maxRetryCount
    }

    void setMaxRetryCount(Integer value) {
        maxRetryCount.set(value)
    }

    /**
     * The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data.
     */
    @Input
    @Optional
    Property<String> getDatafeedUrl() {
        return datafeedUrl
    }

    void setDatafeedUrl(String value) {
        datafeedUrl.set(value)
    }

    /**
     * Credentials used for basic authentication for the NVD API Data feed.
     */
    @Input
    @Optional
    Property<String> getDatafeedUser() {
        return datafeedUser
    }

    void setDatafeedUser(String value) {
        datafeedUser.set(value)
    }

    /**
     * Credentials used for basic authentication for the NVD API Data feed.
     */
    @Input
    @Optional
    Property<String> getDatafeedPassword() {
        return datafeedPassword
    }

    void setDatafeedPassword(String value) {
        datafeedPassword.set(value)
    }

    /**
     * Credentials used for bearer authentication for the NVD API Data feed.
     */
    @Input
    @Optional
    Property<String> getDatafeedBearerToken() {
        return datafeedBearerToken
    }

    void setDatafeedBearerToken(String value) {
        datafeedBearerToken.set(value)
    }

    /**
     * The starting year for the NVD CVE Data feed cache.
     */
    @Input
    @Optional
    Property<Integer> getDatafeedStartYear() {
        return datafeedStartYear
    }

    void setDatafeedStartYear(Integer value) {
        datafeedStartYear.set(value)
    }

    /**
     * The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.
     */
    @Input
    @Optional
    Property<Integer> getValidForHours() {
        return validForHours
    }

    void setValidForHours(Integer value) {
        validForHours.set(value)
    }

    /**
     * The NVD API endpoint URL; configuring this is uncommon.
     */
    @Input
    @Optional
    Property<String> getEndpoint() {
        return endpoint
    }

    void setEndpoint(String value) {
        endpoint.set(value)
    }
}

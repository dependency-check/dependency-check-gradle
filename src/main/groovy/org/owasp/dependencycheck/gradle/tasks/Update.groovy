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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.tasks.TaskAction
import org.gradle.api.InvalidUserDataException
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nvdcve.CveDB
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.reporting.ReportGenerator
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_12_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_20_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_SCHEMA_1_2
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_SCHEMA_2_0
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_START_YEAR
import static org.owasp.dependencycheck.utils.Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PORT
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_SERVER
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_USERNAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.DATA_DIRECTORY
import static org.owasp.dependencycheck.utils.Settings.KEYS.SUPPRESSION_FILE
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS

import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_NAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_CONNECTION_STRING
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_USER
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_PASSWORD

/**
 * Updates the local cache of the NVD CVE data.
 *
 * @author Jeremy Long
 */
class Update extends DefaultTask {

    def config = project.dependencyCheckUpdate

    /**
     * Initializes the update task.
     */
    Update() {
        group = 'OWASP dependency-check'
        description = 'Downloads and stores updates from the NVD CVE data feeds.'
    }

    /**
     * Executes the update task.
     */
    @TaskAction
    def update() {
        initializeSettings()
        def engine = new Engine()
        engine.doUpdates()
        cleanup(engine)
    }

    /**
     * Initializes the settings; if the setting is not configured
     * then the default value from dependency-check-core is used.
     */
    def initializeSettings() {
        Settings.initialize()
        Settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        Settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        Settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        Settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        //Settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        Settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        Settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        Settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        Settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        Settings.setStringIfNotEmpty(DB_USER, config.data.username)
        Settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        Settings.setStringIfNotEmpty(CVE_MODIFIED_12_URL, config.cve.url12Modified)
        Settings.setStringIfNotEmpty(CVE_MODIFIED_20_URL, config.cve.url20Modified)
        Settings.setStringIfNotEmpty(CVE_SCHEMA_1_2, config.cve.url12Base)
        Settings.setStringIfNotEmpty(CVE_SCHEMA_2_0, config.cve.url20Base)

        Settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        Settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)

        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                Settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours);
            } else {
                throw new InvalidUserDataException("Invalid setting: `validForHours` must be 0 or greater");
            }
        }
    }
    /**
     * Relases resources and removes temporary files used.
     */
    def cleanup(engine) {
        Settings.cleanup(true)
        engine.cleanup();
    }
}

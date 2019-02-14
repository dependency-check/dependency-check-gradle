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
import org.gradle.api.GradleException
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.InvalidUserDataException
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.update.exception.UpdateException
import org.owasp.dependencycheck.data.nvdcve.DatabaseException
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_JSON
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_BASE_JSON
import static org.owasp.dependencycheck.utils.Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PORT
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_SERVER
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_USERNAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.DATA_DIRECTORY
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

    @Internal
    def config = project.dependencyCheck
    @Internal
    def settings

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
    update() {
        initializeSettings()
        def engine = null
        try {
            engine = new Engine(settings)
            engine.doUpdates()
        } catch (DatabaseException ex) {
            String msg = "Unable to connect to the dependency-check database"
            if (config.failOnError) {
                throw new GradleException(msg, ex)
            } else {
                logger.error(msg)
            }
        } catch (UpdateException ex) {
            String msg = "Unable to connect to the dependency-check database"
            if (config.failOnError) {
                throw new GradleException(msg, ex)
            } else {
                logger.error(msg)
            }
        }
        if (engine != null) {
            cleanup(engine)
        }
    }

    /**
     * Initializes the settings; if the setting is not configured
     * then the default value from dependency-check-core is used.
     */
    def initializeSettings() {
        settings = new Settings()
        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        //settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        settings.setStringIfNotEmpty(DB_USER, config.data.username)
        settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        settings.setStringIfNotEmpty(CVE_MODIFIED_JSON, config.cve.cveUrlModified)
        settings.setStringIfNotEmpty(CVE_BASE_JSON, config.cve.cveUrlBase)

        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)

        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours)
            } else {
                throw new InvalidUserDataException("Invalid setting: `validForHours` must be 0 or greater")
            }
        }
    }
    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup(engine) {
        settings.cleanup(true)
        engine.close()
    }
}

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
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.DATA_DIRECTORY

/**
 * Purges the local cache of the NVD CVE data.
 */
class Purge extends DefaultTask {

    def config = project.dependencyCheckPurge

    /**
     * Initializes the purge task.
     */
    Purge() {
        group = 'OWASP dependency-check'
        description = 'Purges the local cache of the NVD.'
    }

    /**
     * Purges the local cache of the NVD data.
     */
    @TaskAction
    def purge() {
        initializeSettings()
        def db = new File(Settings.getDataDirectory(), "dc.h2.db")
        if (db.exists()) {
            if (db.delete()) {
                logger.info("Database file purged; local copy of the NVD has been removed")
            } else {
                String msg = "Unable to delete '${db.getAbsolutePath()}'; please delete the file manually"
                if (config.failOnError) {
                    throw new GradleException(msg)
                } else {
                    logger.error(msg)
                }
            }
        } else {
            String msg = "Unable to purge database; the database file does not exists: ${db.getAbsolutePath()}"
            if (config.failOnError) {
                throw new GradleException(msg)
            } else {
                logger.error(msg)
            }
        }
        cleanup()
    }

    /**
     * Initializes the configuration.
     */
    def initializeSettings() {
        Settings.initialize()
        Settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
    }

    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup() {
        Settings.cleanup(true)
    }
}

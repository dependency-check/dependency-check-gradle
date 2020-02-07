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


import org.gradle.api.GradleException
import org.gradle.api.tasks.TaskAction
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nvdcve.DatabaseException
import org.owasp.dependencycheck.data.update.exception.UpdateException

import static org.owasp.dependencycheck.utils.Settings.KEYS.AUTO_UPDATE

/**
 * Updates the local cache of the NVD CVE data.
 *
 * @author Jeremy Long
 */
class Update extends ConfiguredTask {

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
        settings.setBooleanIfNotNull(AUTO_UPDATE, true)
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
            if (config.failOnError) {
                throw new GradleException(ex.getMessage(), ex)
            } else {
                logger.error(ex.getMessage())
            }
        }
        if (engine != null) {
            cleanup(engine)
        }
    }

    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup(engine) {
        if (engine != null) {
            engine.close()
        }
        if (settings != null) {
            settings.cleanup(true)
        }
    }
}

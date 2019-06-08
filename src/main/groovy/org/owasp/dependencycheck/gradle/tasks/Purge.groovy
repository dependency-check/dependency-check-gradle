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


import org.gradle.api.tasks.TaskAction
import org.owasp.dependencycheck.Engine

/**
 * Purges the local cache of the NVD CVE data.
 */
class Purge extends ConfiguredTask {

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
    purge() {
        initializeSettings()
        Engine engine = null
        try {
            engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, getSettings())
            engine.purge()
        } finally {
            if (engine != null) {
                engine.close()
            }
            cleanup()
        }
    }

    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup() {
        if (settings != null) {
            settings.cleanup(true)
        }
    }
}

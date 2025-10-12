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
 * Copyright (c) 2015 Wei Ma. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.util.GradleVersion
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.gradle.DependencyCheckPlugin

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
@groovy.transform.CompileStatic
abstract class Aggregate extends AbstractAnalyze {
    
    private static final GradleVersion CUTOVER_GRADLE_VERSION = GradleVersion.version("4.0")

    Aggregate() {
        group = 'OWASP dependency-check'
        description = 'Identifies and reports known vulnerabilities (CVEs) in multi-project dependencies.'

        if (hasNotCompatibleWithConfigurationCacheOption()) {
            callIncompatibleWithConfigurationCache()
        }
    }

    /**
     * Loads the projects dependencies into the dependency-check analysis engine.
     * Uses configurations captured at configuration time for all projects.
     */
    def scanDependencies(Engine engine) {
        logger.lifecycle("Verifying dependencies for project ${currentProjectName}")
        
        // Use captured configurations from all projects
        if (this.config.scanDependencies) {
            allProjectConfigurations.each { Project proj, List<Configuration> configs ->
                if (shouldBeScanned(proj) && !shouldBeSkipped(proj)) {
                    // Get ProjectInfo from the map to avoid accessing project object
                    ProjectInfo projInfo = projectInfoMap.get(proj)
                    configs.each { Configuration configuration ->
                        if (CUTOVER_GRADLE_VERSION.compareTo(GradleVersion.current()) > 0) {
                            processConfigLegacy configuration, engine
                        } else {
                            processConfigV4 projInfo, configuration, engine
                        }
                    }
                }
            }
        }
        
        if (this.config.scanBuildEnv) {
            allProjectBuildscriptConfigurations.each { Project proj, List<Configuration> configs ->
                if (shouldBeScanned(proj) && !shouldBeSkipped(proj)) {
                    // Get ProjectInfo from the map to avoid accessing project object
                    ProjectInfo projInfo = projectInfoMap.get(proj)
                    configs.each { Configuration configuration ->
                        if (CUTOVER_GRADLE_VERSION.compareTo(GradleVersion.current()) > 0) {
                            processConfigLegacy configuration, engine
                        } else {
                            processConfigV4 projInfo, configuration, engine, true
                        }
                    }
                }
            }
        }
    }
}

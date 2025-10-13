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
import org.gradle.api.tasks.CacheableTask
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.gradle.DependencyCheckPlugin

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
@groovy.transform.CompileStatic
@CacheableTask
class Aggregate extends AbstractAnalyze {

    Aggregate() {
        group = 'OWASP dependency-check'
        description = 'Identifies and reports known vulnerabilities (CVEs) in multi-project dependencies.'

        if (hasNotCompatibleWithConfigurationCacheOption()) {
            callIncompatibleWithConfigurationCache()
        }
    }

    /**
     * Loads the projects dependencies into the dependency-check analysis engine.
     */
    def scanDependencies(Engine engine) {
        logger.lifecycle("Verifying dependencies for project ${currentProjectName}")
        if (project.rootProject.plugins.hasPlugin(DependencyCheckPlugin)) {
            scanProject(project.rootProject.allprojects, engine)
        } else {
            scanProject(project.subprojects, engine)
        }
    }

    private def scanProject(Set<Project> projects, Engine engine) {
        projects.each { Project project ->
            if (shouldBeScanned(project) && !shouldBeSkipped(project)) {
                if (this.config.scanDependencies) {
                    processConfigurations(project, engine)
                }
                if (this.config.scanBuildEnv) {
                    processBuildEnvironment(project, engine)
                }
            }
        }
    }
}

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

package com.tools.security.plugin

import com.tools.security.extension.DependencyCheckConfigurationExtension
import com.tools.security.tasks.DependencyCheckTask
import org.gradle.api.Plugin
import org.gradle.api.Project

class DependencyCheckGradlePlugin implements Plugin<Project> {
    static final String EXTENSION_NAME = 'dependencyCheck'

    @Override
    void apply(Project project) {
        initializeConfigurations(project)
        registerTasks(project)
    }

    def initializeConfigurations(Project project) {
        project.extensions.create(EXTENSION_NAME, DependencyCheckConfigurationExtension)
    }

    def registerTasks(Project project) {
        project.task('dependencyCheck', type: DependencyCheckTask) {
            def extension = project.extensions.findByName(EXTENSION_NAME)
            conventionMapping.proxyServer = { extension.proxyServer }
            conventionMapping.proxyPort = { extension.proxyPort }
            conventionMapping.proxyUsername = { extension.proxyUsername }
            conventionMapping.proxyPassword = { extension.proxyPassword }
            conventionMapping.cveUrl12Modified = { extension.cveUrl12Modified }
            conventionMapping.cveUrl20Modified = { extension.cveUrl20Modified }
            conventionMapping.cveStartYear = { extension.cveStartYear }
            conventionMapping.cveUrl12Base = { extension.cveUrl12Base }
            conventionMapping.cveUrl20Base = { extension.cveUrl20Base }
            conventionMapping.outputDirectory = { extension.outputDirectory }
            conventionMapping.quickQueryTimestamp = { extension.quickQueryTimestamp }
        }
    }
}
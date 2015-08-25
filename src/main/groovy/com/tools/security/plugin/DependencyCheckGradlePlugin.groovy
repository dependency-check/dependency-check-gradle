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

import com.tools.security.extension.DependencyCheckExtension
import com.tools.security.extension.ProxyExtension
import com.tools.security.tasks.DependencyCheckTask
import org.gradle.api.Plugin
import org.gradle.api.Project

class DependencyCheckGradlePlugin implements Plugin<Project> {
    private static final String ROOT_EXTENSION_NAME = 'dependencyCheck'
    private static final String TASK_NAME = 'dependencyCheck'
    private static final String PROXY_EXTENSION_NAME = "proxy"

    @Override
    void apply(Project project) {
        initializeConfigurations(project)
        registerTasks(project)
    }

    def initializeConfigurations(Project project) {
        project.extensions.create(ROOT_EXTENSION_NAME, DependencyCheckExtension)
        project.dependencyCheck.extensions.create(PROXY_EXTENSION_NAME, ProxyExtension)
    }

    def registerTasks(Project project) {
        project.task(TASK_NAME, type: DependencyCheckTask)
    }
}
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

package org.owasp.dependencycheck.gradle

import org.owasp.dependencycheck.gradle.extension.CveExtension
import org.owasp.dependencycheck.gradle.extension.CheckExtension
import org.owasp.dependencycheck.gradle.extension.ProxyExtension
import org.owasp.dependencycheck.gradle.extension.DataExtension
import org.owasp.dependencycheck.gradle.extension.AnalyzerExtension
import org.owasp.dependencycheck.gradle.extension.UpdateExtension
import org.owasp.dependencycheck.gradle.extension.PurgeExtension
import org.owasp.dependencycheck.gradle.extension.PurgeDataExtension
import org.owasp.dependencycheck.gradle.tasks.Check
import org.owasp.dependencycheck.gradle.tasks.Update
import org.owasp.dependencycheck.gradle.tasks.Purge

import org.gradle.api.Plugin
import org.gradle.api.Project
//import org.gradle.api.plugins.ReportingBasePlugin

class DependencyCheck implements Plugin<Project> {
    private static final String CHECK_TASK = 'dependencyCheck'
    private static final String UPDATE_TASK = 'dependencyCheckUpdate'
    private static final String PURGE_TASK = 'dependencyCheckPurge'

    /* configuration extensions */
    private static final String PROXY_EXTENSION_NAME = "proxy"
    private static final String CVE_EXTENSION_NAME = "cve"
    private static final String DATA_EXTENSION_NAME = "data"
    private static final String ANALYZERS_EXTENSION_NAME = "analyzers"

    def void apply(Project project) {
        //TODO figure out how to get the reporting API to work
        //project.plugins.apply(ReportingBasePlugin)
        initializeConfigurations(project)
        registerTasks(project)
    }

    def initializeConfigurations(Project project) {
        def ext = project.extensions.create(CHECK_TASK, CheckExtension)
        ext.extensions.create(PROXY_EXTENSION_NAME, ProxyExtension)
        ext.extensions.create(CVE_EXTENSION_NAME, CveExtension)
        ext.extensions.create(DATA_EXTENSION_NAME, DataExtension)
        ext.extensions.create(ANALYZERS_EXTENSION_NAME, AnalyzerExtension)

        def extu = project.extensions.create(UPDATE_TASK, UpdateExtension)
        extu.extensions.create(CVE_EXTENSION_NAME, CveExtension)
        extu.extensions.create(DATA_EXTENSION_NAME, DataExtension)
        extu.extensions.create(PROXY_EXTENSION_NAME, ProxyExtension)

        def extp = project.extensions.create(PURGE_TASK, PurgeExtension)
        extp.extensions.create(DATA_EXTENSION_NAME, PurgeDataExtension)
    }

    def registerTasks(Project project) {
        project.task(PURGE_TASK, type: Purge)
        project.task(UPDATE_TASK, type: Update)
        project.task(CHECK_TASK, type: Check)
    }
}

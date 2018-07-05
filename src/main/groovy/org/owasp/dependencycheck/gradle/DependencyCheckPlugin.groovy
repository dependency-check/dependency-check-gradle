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

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.owasp.dependencycheck.gradle.extension.AnalyzerExtension
import org.owasp.dependencycheck.gradle.extension.ArtifactoryExtension
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.extension.CveExtension
import org.owasp.dependencycheck.gradle.extension.DataExtension
import org.owasp.dependencycheck.gradle.extension.ProxyExtension
import org.owasp.dependencycheck.gradle.extension.RetireJSExtension
import org.owasp.dependencycheck.gradle.tasks.Update
import org.owasp.dependencycheck.gradle.tasks.Analyze
import org.owasp.dependencycheck.gradle.tasks.Aggregate
import org.owasp.dependencycheck.gradle.tasks.Purge

class DependencyCheckPlugin implements Plugin<Project> {
    public static final String ANALYZE_TASK = 'dependencyCheckAnalyze'
    public static final String AGGREGATE_TASK = 'dependencyCheckAggregate'
    public static final String UPDATE_TASK = 'dependencyCheckUpdate'
    public static final String PURGE_TASK = 'dependencyCheckPurge'

    /* configuration extensions */
    private static final String PROXY_EXTENSION_NAME = "proxy"
    private static final String CVE_EXTENSION_NAME = "cve"
    private static final String DATA_EXTENSION_NAME = "data"
    private static final String CHECK_EXTENSION_NAME = "dependencyCheck"
    private static final String ANALYZERS_EXTENSION_NAME = "analyzers"

    void apply(Project project) {
        initializeConfigurations(project)
        registerTasks(project)
    }
    
    void initializeConfigurations(Project project) {
        def ext = project.extensions.create(CHECK_EXTENSION_NAME, DependencyCheckExtension, project)
        ext.extensions.create(PROXY_EXTENSION_NAME, ProxyExtension)
        ext.extensions.create(CVE_EXTENSION_NAME, CveExtension)
        ext.extensions.create(DATA_EXTENSION_NAME, DataExtension)
        def analyzers = ext.extensions.create(ANALYZERS_EXTENSION_NAME, AnalyzerExtension)
        analyzers.extensions.create('retirejs', RetireJSExtension)
        analyzers.extensions.create('artifactory', ArtifactoryExtension)
    }

    void registerTasks(Project project) {
        project.task(PURGE_TASK, type: Purge)
        project.task(UPDATE_TASK, type: Update)
        project.task(ANALYZE_TASK, type: Analyze)
        project.task(AGGREGATE_TASK, type: Aggregate)
    }
}

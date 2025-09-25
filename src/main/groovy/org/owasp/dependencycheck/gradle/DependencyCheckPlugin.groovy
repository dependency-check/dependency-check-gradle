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

import groovy.transform.CompileStatic
import io.github.jeremylong.jcs3.slf4j.Slf4jAdapter
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.util.GradleVersion
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.tasks.Aggregate
import org.owasp.dependencycheck.gradle.tasks.Analyze
import org.owasp.dependencycheck.gradle.tasks.Purge
import org.owasp.dependencycheck.gradle.tasks.Update
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@CompileStatic
class DependencyCheckPlugin implements Plugin<Project> {
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyCheckPlugin.class);
    static {
        // Quiet noisy loggers
        System.setProperty("jcs.logSystem", "slf4j")
        if (!LOGGER.isDebugEnabled()) {
            Slf4jAdapter.muteLogging(true);
        }
    }

    static final GradleVersion MINIMUM_GRADLE_VERSION = GradleVersion.version("4.0")
    static final GradleVersion REGISTER_TASK_GRADLE_VERSION = GradleVersion.version("4.9")

    public static final String ANALYZE_TASK = 'dependencyCheckAnalyze'
    public static final String AGGREGATE_TASK = 'dependencyCheckAggregate'
    public static final String UPDATE_TASK = 'dependencyCheckUpdate'
    public static final String PURGE_TASK = 'dependencyCheckPurge'

    /* configuration extensions */
    private static final String CHECK_EXTENSION_NAME = "dependencyCheck"

    void apply(Project project) {
        checkGradleVersion(project)
        initializeConfigurations(project)
        registerTasks(project)
    }

    void initializeConfigurations(Project project) {
        project.extensions.create(CHECK_EXTENSION_NAME, DependencyCheckExtension, project)
    }

    void registerTasks(Project project) {
        if (REGISTER_TASK_GRADLE_VERSION.compareTo(GradleVersion.current())<=0) {
            project.tasks.register(PURGE_TASK, Purge)
            project.tasks.register(UPDATE_TASK, Update)
            project.tasks.register(ANALYZE_TASK, Analyze)
            project.tasks.register(AGGREGATE_TASK, Aggregate)
        } else {
            project.task(PURGE_TASK, type: Purge)
            project.task(UPDATE_TASK, type: Update)
            project.task(ANALYZE_TASK, type: Analyze)
            project.task(AGGREGATE_TASK, type: Aggregate)
        }
    }

    void checkGradleVersion(Project project) {
        if (project != null && MINIMUM_GRADLE_VERSION.compareTo(GradleVersion.current()) > 0) {
            if (project.plugins.contains("com.android.build.gradle.AppPlugin")) {
                throw new GradleException("Detected ${GradleVersion.current()}; the dependency-check-gradle " +
                        "plugin requires ${MINIMUM_GRADLE_VERSION} or higher when analyzing Android projects.")
            } else {
                project.logger.warn("Detected ${GradleVersion.current()}; while the dependency-check-gradle " +
                        "plugin will work it is recommended that you upgrade to ${MINIMUM_GRADLE_VERSION} or higher.")
            }
        }
    }
}

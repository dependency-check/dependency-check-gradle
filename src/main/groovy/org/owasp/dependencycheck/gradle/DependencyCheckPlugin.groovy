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
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.tasks.Aggregate
import org.owasp.dependencycheck.gradle.tasks.Analyze
import org.owasp.dependencycheck.gradle.tasks.Purge
import org.owasp.dependencycheck.gradle.tasks.Update

import java.nio.charset.StandardCharsets
import java.util.logging.Level
import java.util.logging.LogManager

@CompileStatic
class DependencyCheckPlugin implements Plugin<Project> {
    public static final String ANALYZE_TASK = 'dependencyCheckAnalyze'
    public static final String AGGREGATE_TASK = 'dependencyCheckAggregate'
    public static final String UPDATE_TASK = 'dependencyCheckUpdate'
    public static final String PURGE_TASK = 'dependencyCheckPurge'

    /* configuration extensions */
    private static final String CHECK_EXTENSION_NAME = "dependencyCheck"

    static {
        muteNoisyLoggers()
    }

    void apply(Project project) {
        initializeConfigurations(project)
        registerTasks(project)
    }

    void initializeConfigurations(Project project) {
        project.extensions.create(CHECK_EXTENSION_NAME, DependencyCheckExtension, project, project.objects)
    }

    void registerTasks(Project project) {
        project.tasks.register(PURGE_TASK, Purge)
        project.tasks.register(UPDATE_TASK, Update)
        project.tasks.register(ANALYZE_TASK, Analyze)
        project.tasks.register(AGGREGATE_TASK, Aggregate)
    }

    /**
     * Hacky method of muting the noisy logging from certain libraries.
     *
     * Normally in ODC we'd rely on the jul-to-slf4j bridge and then configuration of the SLF4J logging backend, but
     * we shouldn't make assumptions about the backend within Gradle, and Gradle has its own logging bridges;
     * so all we can really do is adjust java.util.logging configuration directly
     */
    private static void muteNoisyLoggers() {
        // Mirrors the configuration within cli/src/main/resources/logback.xml
        final String noisyJavaUtilLoggerConfig = Map.of(
                "org.apache.lucene", Level.SEVERE,
        ).collect { cat -> "${cat.key}.level = ${cat.value}" }.join(System.lineSeparator())

        try (def configStream = new ByteArrayInputStream(noisyJavaUtilLoggerConfig.getBytes(StandardCharsets.UTF_8))) {
            LogManager.logManager.updateConfiguration(configStream, null)
        }
    }
}

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
import org.gradle.api.artifacts.Configuration
import org.gradle.util.GradleVersion
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.tasks.AbstractAnalyze
import org.owasp.dependencycheck.gradle.tasks.Aggregate
import org.owasp.dependencycheck.gradle.tasks.Analyze
import org.owasp.dependencycheck.gradle.tasks.ProjectInfo
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
        project.extensions.create(CHECK_EXTENSION_NAME, DependencyCheckExtension, project, project.objects)
    }

    void registerTasks(Project project) {
        if (REGISTER_TASK_GRADLE_VERSION.compareTo(GradleVersion.current()) <= 0) {
            project.tasks.register(PURGE_TASK, Purge)
            project.tasks.register(UPDATE_TASK, Update)
            project.tasks.register(ANALYZE_TASK, Analyze) { task ->
                initializeProjectProperties(task, project)
            }
            project.tasks.register(AGGREGATE_TASK, Aggregate) { task ->
                initializeAggregateTaskProperties(task, project)
            }
        } else {
            project.task(PURGE_TASK, type: Purge)
            project.task(UPDATE_TASK, type: Update)
            def analyzeTask = project.task(ANALYZE_TASK, type: Analyze) as Analyze
            initializeProjectProperties(analyzeTask, project)
            def aggregateTask = project.task(AGGREGATE_TASK, type: Aggregate) as Aggregate
            initializeAggregateTaskProperties(aggregateTask, project)
        }
    }
    
    private void initializeAggregateTaskProperties(AbstractAnalyze task, Project project) {
        // First initialize the base project properties
        initializeProjectProperties(task, project)
        
        // For Aggregate task, capture configurations from all projects at configuration time
        Set<Project> projectsToScan = project.rootProject.plugins.hasPlugin(DependencyCheckPlugin) ?
            project.rootProject.allprojects : project.subprojects
            
        projectsToScan.each { Project proj ->
            // Capture project metadata
            task.projectInfoMap.put(proj, ProjectInfo.from(proj))
            
            // Capture this project's configurations
            def configs = proj.configurations.findAll { Configuration config ->
                shouldScanConfiguration(task, config)
            }.toList()
            if (!configs.isEmpty()) {
                task.allProjectConfigurations.put(proj, configs)
            }
            
            // Capture this project's buildscript configurations
            def buildConfigs = proj.buildscript.configurations.findAll { Configuration config ->
                shouldScanConfiguration(task, config)
            }.toList()
            if (!buildConfigs.isEmpty()) {
                task.allProjectBuildscriptConfigurations.put(proj, buildConfigs)
            }
        }
    }
    
    private void initializeProjectProperties(AbstractAnalyze task, Project project) {
        task.projectName.set(project.name)
        task.projectGroup.set(project.group?.toString() ?: "")
        task.projectVersion.set(project.version?.toString() ?: "")
        task.projectBuildFile.set(project.buildFile)
        task.projectPath.set(project.path)
        task.offlineMode.set(project.gradle.startParameter.offline)
        task.projectDirectory.set(project.layout.projectDirectory)
        task.dependencyHandler = project.dependencies
        task.currentProjectInfo = ProjectInfo.from(project)
        
        // Set display name, handling legacy Gradle versions
        if (project.metaClass.respondsTo(project, "getDisplayName")) {
            task.projectDisplayName.set(project.displayName)
        } else {
            task.projectDisplayName.set(project.name)
        }
        
        // Capture scan paths at configuration time
        task.scanPaths.set([
            'src/main/resources', 'src/main/webapp',
            './package.json', './package-lock.json',
            './npm-shrinkwrap.json', './yarn.lock',
            './pnpm.lock', 'pnpm-lock.yaml', './Gopkg.lock', './go.mod'
        ])
        
        // Capture configurations to scan at configuration time
        // The Configuration objects themselves are captured now, but they will be
        // resolved later at execution time when we iterate over their artifacts
        task.configurationsToScanList.addAll(
            project.configurations.findAll { Configuration config ->
                shouldScanConfiguration(task, config)
            }
        )
        
        task.buildscriptConfigurationsToScanList.addAll(
            project.buildscript.configurations.findAll { Configuration config ->
                shouldScanConfiguration(task, config)
            }
        )
    }
    
    private boolean shouldScanConfiguration(AbstractAnalyze task, Configuration configuration) {
        def ext = task.project.extensions.findByType(DependencyCheckExtension)
        if (ext == null) return false
        
        boolean shouldScan = ext.scanConfigurations.get().isEmpty() || ext.scanConfigurations.get().contains(configuration.name)
        boolean shouldSkip = ext.skipConfigurations.get().contains(configuration.name)
        boolean shouldSkipAsTest = ext.skipTestGroups.get() && isTestConfiguration(configuration)
        boolean canResolve = configuration.metaClass.respondsTo(configuration, "isCanBeResolved") ? 
            configuration.isCanBeResolved() : true
            
        return shouldScan && !shouldSkip && !shouldSkipAsTest && canResolve
    }
    
    private static boolean isTestConfiguration(Configuration configuration) {
        boolean isTestConfig = configuration.name =~ /((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/
        configuration.hierarchy.each {
            isTestConfig |= (it.name =~ /((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/) as boolean
        }
        return isTestConfig
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

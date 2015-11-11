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

package com.tools.security.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.tasks.TaskAction
import org.gradle.api.GradleException
import org.gradle.api.InvalidUserDataException

import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nvdcve.CveDB
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.reporting.ReportGenerator
import org.owasp.dependencycheck.utils.Settings
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;


import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_12_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_20_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_SCHEMA_1_2
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_SCHEMA_2_0
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_START_YEAR
import static org.owasp.dependencycheck.utils.Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PORT
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_SERVER
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_USERNAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.AUTO_UPDATE
import static org.owasp.dependencycheck.utils.Settings.KEYS.DATA_DIRECTORY
import static org.owasp.dependencycheck.utils.Settings.KEYS.SUPPRESSION_FILE

import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_NAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_CONNECTION_STRING
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_USER
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_PASSWORD

import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_JAR_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NUSPEC_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_CENTRAL_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_USES_PROXY
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARCHIVE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OPENSSL_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_CMAKE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_AUTOCONF_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
class Check extends DefaultTask {

    def currentProjectName = project.getName()
    def config = project.dependencyCheck

    /**
     * Initializes the check task.
     */
    Check() {
        group = 'OWASP dependency-check'
        description = 'Produce dependency security report.'
    }

    /**
     * Calls dependency-check-core's analysis engine to scan
     * all of the projects dependencies.
     */
    @TaskAction
    def check() {
        initializeSettings()
        def engine = new Engine()

        scanDependencies(engine)
        analyzeDependencies(engine)
        generateReport(engine)
        showSummary(engine)
        checkForFailure(engine)
        cleanup(engine)
    }

    /**
     * Initializes the settings object. If the setting is not set the
     * default from dependency-check-core is used.
     */
    def initializeSettings() {
        Settings.initialize()

        Settings.setBooleanIfNotNull(AUTO_UPDATE, config.autoUpdate)
        Settings.setStringIfNotEmpty(SUPPRESSION_FILE, config.suppressionFile)

        Settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        Settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        Settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        Settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        //Settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        Settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        Settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        Settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        Settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        Settings.setStringIfNotEmpty(DB_USER, config.data.username)
        Settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        Settings.setStringIfNotEmpty(CVE_MODIFIED_12_URL, config.cve.url12Modified)
        Settings.setStringIfNotEmpty(CVE_MODIFIED_20_URL, config.cve.url20Modified)
        Settings.setStringIfNotEmpty(CVE_SCHEMA_1_2, config.cve.url12Base)
        Settings.setStringIfNotEmpty(CVE_SCHEMA_2_0, config.cve.url20Base)

        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                Settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours);
            } else {
                throw new InvalidUserDataException("Invalid setting: `validForHours` must be 0 or greater");
            }
        }
        Settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, config.analyzer.jarEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, config.analyzer.nuspecEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, config.analyzer.centralEnabled)

        Settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, config.analyzer.nexusEnabled)
        Settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, config.analyzer.nexusUrl)
        Settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, config.analyzer.nexusUsesProxy)

        Settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, config.analyzer.archiveEnabled)
        Settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, config.analyzer.zipExtensions)
        Settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, config.analyzer.assemblyEnabled)
        Settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_MONO_PATH, config.analyzer.pathToMono)

        Settings.setBooleanIfNotNull(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, config.analyzer.pyDistributionEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_PYTHON_PACKAGE_ENABLED, config.analyzer.pyPackageEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_RUBY_GEMSPEC_ENABLED, config.analyzer.rubygemsEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_OPENSSL_ENABLED, config.analyzer.opensslEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_CMAKE_ENABLED, config.analyzer.cmakeEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_AUTOCONF_ENABLED, config.analyzer.autoconfEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_ENABLED, config.analyzer.composerEnabled)
        Settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, config.analyzer.nodeEnabled)
    }
    /**
     * Relases resources and removes temporary files used.
     */
    def cleanup(engine) {
        Settings.cleanup(true)
        engine.cleanup();
    }

    /**
     * Loads the projects dependencies into the dependency-check analysis engine.
     */
    def scanDependencies(engine) {
        logger.lifecycle("Verifying dependencies for project ${currentProjectName}")
        getAllDependencies(project).each {
            engine.scan(it)
        }
    }

    /**
     * Performs the dependency-check analysis.
     */
    def analyzeDependencies(Engine engine) {
        logger.lifecycle("Checking for updates and analyzing vulnerabilities for dependencies")
        engine.analyzeDependencies()
    }

    /**
     * Displays a summary of the dependency-check results to the build console.
     */
    def showSummary(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.lifecycle("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
        if (config.showSummary) {
            final StringBuilder summary = new StringBuilder()
            for (Dependency d : engine.getDependencies()) {
                boolean firstEntry = true
                final StringBuilder ids = new StringBuilder()
                for (Vulnerability v : d.getVulnerabilities()) {
                    if (firstEntry) {
                        firstEntry = false
                    } else {
                        ids.append(", ")
                    }
                    ids.append(v.getName())
                }
                if (ids.length() > 0) {
                    summary.append(d.getFileName()).append(" (")
                    firstEntry = true
                    for (Identifier id : d.getIdentifiers()) {
                        if (firstEntry) {
                            firstEntry = false
                        } else {
                            summary.append(", ")
                        }
                        summary.append(id.getValue())
                    }
                    summary.append(") : ").append(ids).append('\n')
                }
            }
            if (summary.length() > 0) {
                final String msg = String.format("%n%n"
                    + "One or more dependencies were identified with known vulnerabilities:%n%n%s"
                    + "%n%nSee the dependency-check report for more details.%n%n", summary.toString())
                logger.lifecycle(msg)
            }
        }

    }

    /**
     * If configured, fails the build if a vulnerability is identified with a CVSS
     * score higher then the failure threshold configured.
     */
    def checkForFailure(Engine engine) {
        if (config.failBuildOnCVSS>10) {
            return
        }

        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        final StringBuilder ids = new StringBuilder();

        vulnerabilities.each {
            if (it.getCvssScore() >= config.failBuildOnCVSS) {
                if (ids.length() == 0) {
                    ids.append(it.getName());
                } else {
                    ids.append(", ").append(it.getName());
                }
            }
        }
        if (ids.length() > 0) {
            final String msg = String.format("%n%nDependency-Check Failure:%n"
                + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater then '%.1f': %s%n"
                + "See the dependency-check report for more details.%n%n", config.failBuildOnCVSS, ids.toString());
            throw new GradleException(msg);
        }

    }
    /**
     * Writes the report(s) to the configured output directory.
     */
    def generateReport(Engine engine) {
        logger.lifecycle("Generating report for project ${currentProjectName}")
        def reportGenerator = new ReportGenerator(currentProjectName, engine.dependencies, engine.analyzers,
            new CveDB().databaseProperties)

        reportGenerator.generateReports("$project.buildDir/${config.reportsDirName}", config.format)
    }

    /**
     * Returns all dependencies associated wtihin the configured dependency groups. Test
     * groups can be excluded by setting the skipTestGroups configuration to true.
     */
    def getAllDependencies(project) {
        return project.getConfigurations().findAll {
            !config.skipTestGroups || (config.skipTestGroups && !it.getName().startsWith("test"))
        }.collect {
            it.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
                artifact.getFile()
            }
        }.flatten().unique();
    }
}

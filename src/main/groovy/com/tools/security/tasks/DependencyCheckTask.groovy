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
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nvdcve.CveDB
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.reporting.ReportGenerator
import org.owasp.dependencycheck.utils.Settings

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
import static org.owasp.dependencycheck.utils.Settings.setBoolean
import static org.owasp.dependencycheck.utils.Settings.setString

class DependencyCheckTask extends DefaultTask {

    def currentProjectName = project.getName()
    def config = project.dependencyCheck

    DependencyCheckTask() {
        group = 'Dependency Check'
        description = 'Produce dependency security report.'
    }

    @TaskAction
    def check() {
        initializeSettings()
        def engine = initializeEngine()

        verifyDependencies(engine)
        analyzeDependencies(engine)
        retrieveVulnerabilities(engine)
        generateReport(engine)

        cleanup(engine)
    }

    private Engine initializeEngine() {
        new Engine()
    }

    def initializeSettings() {
        Settings.initialize()
        overrideProxySetting()
        overrideCveUrlSetting()
        overrideDownloaderSetting()
    }

    def cleanup(engine) {
        Settings.cleanup(true)
        engine.cleanup();
    }

    def verifyDependencies(engine) {
        logger.lifecycle("Verifying dependencies for project ${currentProjectName}")
        getAllDependencies(project).each { engine.scan(it) }
    }

    def analyzeDependencies(Engine engine) {
        logger.lifecycle("Checking for updates and analyzing vulnerabilities for dependencies")
        engine.analyzeDependencies()
    }

    def retrieveVulnerabilities(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.lifecycle("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
    }

    def generateReport(Engine engine) {
        logger.lifecycle("Generating report for project ${currentProjectName}")
        def reportGenerator = new ReportGenerator(currentProjectName, engine.dependencies, engine.analyzers,
            new CveDB().databaseProperties)

        reportGenerator.generateReports(generateReportDirectory(currentProjectName), ReportGenerator.Format.ALL)
    }

    def generateReportDirectory(String currentProjectName) {
        "${config.outputDirectory}/${currentProjectName}"
    }

    def overrideProxySetting() {
        if (isProxySettingExist()) {
            logger.lifecycle("Using proxy ${config.proxyServer}:${config.proxyPort}")

            overrideStringBasedSettingWhenProvided(PROXY_SERVER, config.proxyServer)
            overrideStringBasedSettingWhenProvided(PROXY_PORT, "${config.proxyPort}")
            overrideStringBasedSettingWhenProvided(PROXY_USERNAME, config.proxyUsername)
            overrideStringBasedSettingWhenProvided(PROXY_PASSWORD, config.proxyPassword)
        }
    }

    def isProxySettingExist() {
        config.proxyServer != null && config.proxyPort != null
    }

    def getAllDependencies(project) {
        return project.getConfigurations().collect { Configuration configuration ->
            configuration.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
                artifact.getFile()
            }
        }.flatten();
    }

    def overrideCveUrlSetting() {
        overrideStringBasedSettingWhenProvided(CVE_MODIFIED_20_URL, config.cveUrl20Modified)
        overrideStringBasedSettingWhenProvided(CVE_MODIFIED_12_URL, config.cveUrl12Modified)
        overrideIntegerBasedSettingWhenProvided(CVE_START_YEAR, config.cveStartYear)
        overrideStringBasedSettingWhenProvided(CVE_SCHEMA_2_0, config.cveUrl20Base)
        overrideStringBasedSettingWhenProvided(CVE_SCHEMA_1_2, config.cveUrl12Base)
    }

    def overrideDownloaderSetting() {
        overrideBooleanBasedSettingWhenProvided(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)
    }

    private overrideStringBasedSettingWhenProvided(String key, String providedValue) {
        if (providedValue != null) {
            logger.lifecycle("Setting [${key}] overrided with value [${providedValue}]")
            setString(key, providedValue)
        }
    }

    private overrideIntegerBasedSettingWhenProvided(String key, Integer providedValue) {
        if (providedValue != null) {
            logger.lifecycle("Setting [${key}] overrided with value [${providedValue}]")
            setString(key, "${providedValue}")
        }
    }

    private overrideBooleanBasedSettingWhenProvided(String key, Boolean providedValue) {
        if (providedValue != null) {
            logger.lifecycle("Setting [${key}] overrided with value [${providedValue}]")
            setBoolean(key, providedValue)
        }
    }
}

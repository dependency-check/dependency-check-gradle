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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.InvalidUserDataException
import org.gradle.api.tasks.Internal
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARCHIVE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_AUTOCONF_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_CENTRAL_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_CMAKE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_COCOAPODS_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_JAR_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NEXUS_USES_PROXY
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NUGETCONF_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_NUSPEC_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OPENSSL_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OSSINDEX_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OSSINDEX_USER
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RETIREJS_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RETIREJS_FILTERS
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED
import static org.owasp.dependencycheck.utils.Settings.KEYS.AUTO_UPDATE
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_BASE_JSON
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS
import static org.owasp.dependencycheck.utils.Settings.KEYS.CVE_MODIFIED_JSON
import static org.owasp.dependencycheck.utils.Settings.KEYS.DATA_DIRECTORY
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_CONNECTION_STRING
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_NAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_DRIVER_PATH
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.DB_USER
import static org.owasp.dependencycheck.utils.Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP
import static org.owasp.dependencycheck.utils.Settings.KEYS.HINTS_FILE
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PASSWORD
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_PORT
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_SERVER
import static org.owasp.dependencycheck.utils.Settings.KEYS.PROXY_USERNAME
import static org.owasp.dependencycheck.utils.Settings.KEYS.SUPPRESSION_FILE

/**
 * Standard class to read in the configuration and populated the ODC settings.
 *
 * @author Jeremy Long
 */
abstract class ConfiguredTask extends DefaultTask {
    @Internal
    def config = project.dependencyCheck
    @Internal
    def settings
    @Internal
    def PROPERTIES_FILE = "task.properties"

    /**
     * Initializes the settings object. If the setting is not set the
     * default from dependency-check-core is used.
     */
    protected void initializeSettings() {
        settings = new Settings()

        InputStream taskProperties = null
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE)
            settings.mergeProperties(taskProperties)
        } catch (IOException ex) {
            logger.warn("Unable to load the dependency-check gradle task.properties file.")
            logger.debug("", ex)
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close()
                } catch (IOException ex) {
                    logger.debug("", ex)
                }
            }
        }
        settings.setBooleanIfNotNull(AUTO_UPDATE, config.autoUpdate)

        String[] suppressionLists = determineSuppressions(config.suppressionFiles, config.suppressionFile)

        settings.setArrayIfNotEmpty(SUPPRESSION_FILE, suppressionLists)
        settings.setStringIfNotEmpty(HINTS_FILE, config.hintsFile)

        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        //settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        settings.setStringIfNotEmpty(DB_USER, config.data.username)
        settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        settings.setStringIfNotEmpty(CVE_MODIFIED_JSON, config.cve.urlModified)
        settings.setStringIfNotEmpty(CVE_BASE_JSON, config.cve.urlBase)
        settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)

        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours)
            } else {
                throw new InvalidUserDataException("Invalid setting: `validForHours` must be 0 or greater")
            }
        }
        settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, config.analyzers.jarEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, config.analyzers.nuspecEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, config.analyzers.ossIndexEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, config.analyzers.ossIndex.enabled)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_USER, config.analyzers.ossIndex.username)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_PASSWORD, config.analyzers.ossIndex.password)

        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, config.analyzers.centralEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, config.analyzers.nexusEnabled)
        settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, config.analyzers.nexusUrl)
        settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, config.analyzers.nexusUsesProxy)

        settings.setBooleanIfNotNull(ANALYZER_EXPERIMENTAL_ENABLED, config.analyzers.experimentalEnabled)
        settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, config.analyzers.archiveEnabled)
        settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, config.analyzers.zipExtensions)
        settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, config.analyzers.assemblyEnabled)
        settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_DOTNET_PATH, config.analyzers.pathToDotnet)

        settings.setBooleanIfNotNull(ANALYZER_COCOAPODS_ENABLED, config.analyzers.cocoapodsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, config.analyzers.swiftEnabled)
        settings.setBooleanIfNotNull(ANALYZER_BUNDLE_AUDIT_ENABLED, config.analyzers.bundleAuditEnabled)
        settings.setStringIfNotEmpty(ANALYZER_BUNDLE_AUDIT_PATH, config.analyzers.pathToBundleAudit)

        settings.setBooleanIfNotNull(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, config.analyzers.pyDistributionEnabled)
        settings.setBooleanIfNotNull(ANALYZER_PYTHON_PACKAGE_ENABLED, config.analyzers.pyPackageEnabled)
        settings.setBooleanIfNotNull(ANALYZER_RUBY_GEMSPEC_ENABLED, config.analyzers.rubygemsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OPENSSL_ENABLED, config.analyzers.opensslEnabled)
        settings.setBooleanIfNotNull(ANALYZER_CMAKE_ENABLED, config.analyzers.cmakeEnabled)
        settings.setBooleanIfNotNull(ANALYZER_AUTOCONF_ENABLED, config.analyzers.autoconfEnabled)
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_ENABLED, config.analyzers.composerEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUGETCONF_ENABLED, config.analyzers.nugetconfEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, config.analyzers.nodeEnabled)
        if (config.analyzers.nspEnabled != null) {
            logger.error("The nspAnalyzerEnabled configuration has been deprecated and replaced by nodeAuditAnalyzerEnabled");
            logger.error("The nspAnalyzerEnabled configuration will be removed in the next major release");
            settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, config.analyzers.nspEnabled);
        }
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, config.analyzers.nodeAuditEnabled);

        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_ENABLED, config.analyzers.retirejs.enabled)
        settings.setStringIfNotNull(ANALYZER_RETIREJS_REPO_JS_URL, config.analyzers.retirejs.retireJsUrl)
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, config.analyzers.retirejs.filterNonVulnerable)
        settings.setArrayIfNotEmpty(ANALYZER_RETIREJS_FILTERS, config.analyzers.retirejs.filters)

        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_ENABLED, config.analyzers.artifactory.enabled)
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, config.analyzers.artifactory.parallelAnalysis)
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_USES_PROXY, config.analyzers.artifactory.usesProxy)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_URL, config.analyzers.artifactory.url)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_TOKEN, config.analyzers.artifactory.apiToken)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_USERNAME, config.analyzers.artifactory.username)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_BEARER_TOKEN, config.analyzers.artifactory.bearerToken)

        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_USE_CACHE, config.cache.nodeAudit)
        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_USE_CACHE, config.cache.central)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_USE_CACHE, config.cache.ossInex)
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions(suppressionFiles, suppressionFile) {
        if (suppressionFile != null) {
            suppressionFiles << suppressionFile
        }
        suppressionFiles
    }
}

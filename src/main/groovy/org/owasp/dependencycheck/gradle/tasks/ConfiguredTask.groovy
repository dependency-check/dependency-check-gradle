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

import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.gradle.internal.resource.transport.http.HttpProxySettings
import org.gradle.internal.resource.transport.http.JavaSystemPropertiesSecureHttpProxySettings
import org.gradle.internal.resource.transport.http.JavaSystemPropertiesHttpProxySettings
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.*

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
    def PROPERTIES_FILE = 'task.properties'

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
            logger.warn('Unable to load the dependency-check gradle task.properties file.')
            logger.debug('', ex)
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

        configureProxy(settings)

        configureSlack(settings)

        //settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        settings.setStringIfNotEmpty(DB_USER, config.data.username)
        settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        settings.setStringIfNotEmpty(CVE_MODIFIED_JSON, config.cve.urlModified)
        settings.setStringIfNotEmpty(CVE_BASE_JSON, config.cve.urlBase)
        settings.setStringIfNotEmpty(CVE_DOWNLOAD_WAIT_TIME, config.waitTime)
        if (config.startYear != null) {
            if (config.startYear >= 2002) {
                settings.setInt(CVE_START_YEAR, config.startYear)
            } else {
                throw new InvalidUserDataException('Invalid setting: `validForHours` must be 0 or greater')
            }
        }
        if (config.cve.user && config.cve.password) {
            settings.setStringIfNotEmpty(CVE_USER, config.cve.user)
            settings.setStringIfNotEmpty(CVE_PASSWORD, config.cve.password)
        }
        settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)
        settings.setFloat(JUNIT_FAIL_ON_CVSS, config.junitFailOnCVSS)
        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours)
            } else {
                throw new InvalidUserDataException('Invalid setting: `validForHours` must be 0 or greater')
            }
        }
        settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, config.analyzers.jarEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, config.analyzers.nuspecEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, select(config.analyzers.ossIndex.enabled, config.analyzers.ossIndexEnabled))
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, config.analyzers.ossIndex.enabled)
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_USER, config.analyzers.ossIndex.username)
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_PASSWORD, config.analyzers.ossIndex.password)

        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, config.analyzers.centralEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, config.analyzers.nexusEnabled)
        settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, config.analyzers.nexusUrl)
        settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, config.analyzers.nexusUsesProxy)

        settings.setBooleanIfNotNull(ANALYZER_EXPERIMENTAL_ENABLED, config.analyzers.experimentalEnabled)
        settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, config.analyzers.archiveEnabled)
        settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, config.analyzers.zipExtensions)
        settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, config.analyzers.assemblyEnabled)
        settings.setBooleanIfNotNull(ANALYZER_MSBUILD_PROJECT_ENABLED, config.analyzers.msbuildEnabled)
        settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_DOTNET_PATH, config.analyzers.pathToDotnet)
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_DEP_ENABLED, config.analyzers.golangDepEnabled)
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_MOD_ENABLED, config.analyzers.golangModEnabled)
        settings.setStringIfNotNull(ANALYZER_GOLANG_PATH, config.analyzers.pathToGo)

        settings.setBooleanIfNotNull(ANALYZER_COCOAPODS_ENABLED, config.analyzers.cocoapodsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, config.analyzers.swiftEnabled)
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED, config.analyzers.swiftPackageResolvedEnabled)
        settings.setBooleanIfNotNull(ANALYZER_BUNDLE_AUDIT_ENABLED, config.analyzers.bundleAuditEnabled)
        settings.setStringIfNotEmpty(ANALYZER_BUNDLE_AUDIT_PATH, config.analyzers.pathToBundleAudit)

        settings.setBooleanIfNotNull(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, config.analyzers.pyDistributionEnabled)
        settings.setBooleanIfNotNull(ANALYZER_PYTHON_PACKAGE_ENABLED, config.analyzers.pyPackageEnabled)
        settings.setBooleanIfNotNull(ANALYZER_RUBY_GEMSPEC_ENABLED, config.analyzers.rubygemsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OPENSSL_ENABLED, config.analyzers.opensslEnabled)
        settings.setBooleanIfNotNull(ANALYZER_CMAKE_ENABLED, config.analyzers.cmakeEnabled)
        settings.setBooleanIfNotNull(ANALYZER_AUTOCONF_ENABLED, config.analyzers.autoconfEnabled)
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_ENABLED, config.analyzers.composerEnabled)
        settings.setBooleanIfNotNull(ANALYZER_CPANFILE_ENABLED, config.analyzers.cpanEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUGETCONF_ENABLED, config.analyzers.nugetconfEnabled)


        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, config.analyzers.nodeEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, select(config.analyzers.nodeAudit.enabled, config.analyzers.nodeAuditEnabled))
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_USE_CACHE, config.analyzers.nodeAudit.useCache)
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_SKIPDEV, config.analyzers.nodeAudit.skipDevDependencies)
        settings.setBooleanIfNotNull(ANALYZER_YARN_AUDIT_ENABLED, config.analyzers.nodeAudit.yarnEnabled)
        settings.setStringIfNotNull(ANALYZER_YARN_PATH, config.analyzers.nodeAudit.yarnPath);
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_ENABLED, config.analyzers.retirejs.enabled)
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_FORCEUPDATE, config.analyzers.retirejs.forceupdate)
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
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_USE_CACHE, config.cache.ossIndex)
    }

    private void configureSlack(Settings settings) {
        settings.setBooleanIfNotNull(SlackNotificationSenderService.SLACK__WEBHOOK__ENABLED, config.slack.enabled)
        settings.setStringIfNotEmpty(SlackNotificationSenderService.SLACK__WEBHOOK__URL, config.slack.webhookUrl)
    }

    private void configureProxy(Settings settings) {
        if (config.proxy.server) {
            project.logger.warn("Deprecated configuration `proxy { server='${config.proxy.server}' }`; please update your configuration to use the gradle proxy configuration")
        }
        HttpProxySettings proxyGradle = new JavaSystemPropertiesSecureHttpProxySettings()
        if (proxyGradle.proxy == null) {  // if systemProp.https.proxyHost is not defined, fallback to http proxy
            proxyGradle = new JavaSystemPropertiesHttpProxySettings()
        }
        if (proxyGradle.proxy != null && proxyGradle.proxy.host != null) {
            config.proxy.server = proxyGradle.proxy.host
            config.proxy.port = proxyGradle.proxy.port
            if (proxyGradle.proxy.credentials != null) {
                if (proxyGradle.proxy.credentials.username != null) {
                    config.proxy.username = proxyGradle.proxy.credentials.username
                }
                if (proxyGradle.proxy.credentials.password != null) {
                    config.proxy.password = proxyGradle.proxy.credentials.password
                }
            }
            if (proxyGradle.hasProperty('nonProxyHosts') && proxyGradle.nonProxyHosts) {
                config.proxy.nonProxyHosts = proxyGradle.nonProxyHosts
            }
        }
        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        settings.setArrayIfNotEmpty(PROXY_NON_PROXY_HOSTS, config.proxy.nonProxyHosts)
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
    /**
     * Selects the current configiguration option - returns the deprecated option if the current configuration option is null
     * @param current the current configuration
     * @param deprecated the deprecated configuration
     * @return the current configuration option if not null; otherwise the deprecated option is returned
     */
    private Boolean select(Boolean current, Boolean deprecated) {
        return current != null ? current : deprecated
    }
}

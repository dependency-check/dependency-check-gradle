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

import com.google.common.base.Strings
import org.gradle.api.DefaultTask
import org.gradle.api.InvalidUserDataException
import org.gradle.api.tasks.Internal
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.owasp.dependencycheck.utils.Downloader
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.KEYS.*

/**
 * Standard class to read in the configuration and populated the ODC settings.
 *
 * @author Jeremy Long
 */
@groovy.transform.CompileStatic
abstract class ConfiguredTask extends DefaultTask {

    @Internal
    DependencyCheckExtension config = (DependencyCheckExtension) project.getExtensions().findByName('dependencyCheck')
    @Internal
    Settings settings
    @Internal
    String PROPERTIES_FILE = 'task.properties'

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
        settings.setStringIfNotEmpty(SUPPRESSION_FILE_USER, config.suppressionFileUser)
        settings.setStringIfNotEmpty(SUPPRESSION_FILE_PASSWORD, config.suppressionFilePassword)
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


        settings.setStringIfNotEmpty(NVD_API_KEY, config.nvd.apiKey)
        settings.setStringIfNotEmpty(NVD_API_ENDPOINT, config.nvd.endpoint)
        settings.setIntIfNotNull(NVD_API_DELAY, config.nvd.delay)
        settings.setIntIfNotNull(NVD_API_RESULTS_PER_PAGE, config.nvd.resultsPerPage)
        settings.setIntIfNotNull(NVD_API_MAX_RETRY_COUNT, config.nvd.maxRetryCount)
        settings.setIntIfNotNull(NVD_API_VALID_FOR_HOURS, config.nvd.validForHours);

        settings.setStringIfNotEmpty(NVD_API_DATAFEED_URL, config.nvd.datafeedUrl)
        if (config.nvd.datafeedUser && config.nvd.datafeedPassword) {
            settings.setStringIfNotEmpty(NVD_API_DATAFEED_USER, config.nvd.datafeedUser)
            settings.setStringIfNotEmpty(NVD_API_DATAFEED_PASSWORD, config.nvd.datafeedPassword)
        }

        settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)
        settings.setFloat(JUNIT_FAIL_ON_CVSS, config.junitFailOnCVSS)
        settings.setBooleanIfNotNull(HOSTED_SUPPRESSIONS_ENABLED, config.hostedSuppressions.enabled)
        settings.setBooleanIfNotNull(HOSTED_SUPPRESSIONS_FORCEUPDATE, config.hostedSuppressions.forceupdate)
        settings.setStringIfNotNull(HOSTED_SUPPRESSIONS_URL, config.hostedSuppressions.url)
        if (config.hostedSuppressions.validForHours != null) {
            if (config.hostedSuppressions.validForHours >= 0) {
                settings.setInt(HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, config.hostedSuppressions.validForHours)
            } else {
                throw new InvalidUserDataException('Invalid setting: `validForHours` must be 0 or greater')
            }
        }
        settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, config.analyzers.jarEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, config.analyzers.nuspecEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, select(config.analyzers.ossIndex.enabled, config.analyzers.ossIndexEnabled))
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, config.analyzers.ossIndex.warnOnlyOnRemoteErrors)
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, config.analyzers.ossIndex.enabled)
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_USER, config.analyzers.ossIndex.username)
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_PASSWORD, config.analyzers.ossIndex.password)
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_URL, config.analyzers.ossIndex.url)

        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, config.analyzers.centralEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, config.analyzers.nexusEnabled)
        settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, config.analyzers.nexusUrl)
        settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, config.analyzers.nexusUsesProxy)

        settings.setBooleanIfNotNull(ANALYZER_EXPERIMENTAL_ENABLED, config.analyzers.experimentalEnabled)
        settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, config.analyzers.archiveEnabled)
        settings.setBooleanIfNotNull(ANALYZER_KNOWN_EXPLOITED_ENABLED, config.analyzers.knownExploitedEnabled)
        settings.setStringIfNotNull(KEV_URL, config.analyzers.knownExploitedURL)
        settings.setIntIfNotNull(KEV_CHECK_VALID_FOR_HOURS, config.analyzers.knownExploitedValidForHours)
        settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, config.analyzers.zipExtensions)
        settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, config.analyzers.assemblyEnabled)
        settings.setBooleanIfNotNull(ANALYZER_MSBUILD_PROJECT_ENABLED, config.analyzers.msbuildEnabled)
        settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_DOTNET_PATH, config.analyzers.pathToDotnet)
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_DEP_ENABLED, config.analyzers.golangDepEnabled)
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_MOD_ENABLED, config.analyzers.golangModEnabled)
        settings.setStringIfNotNull(ANALYZER_GOLANG_PATH, config.analyzers.pathToGo)

        settings.setBooleanIfNotNull(ANALYZER_COCOAPODS_ENABLED, config.analyzers.cocoapodsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, config.analyzers.swiftEnabled)
        settings.setBooleanIfNotNull(ANALYZER_DART_ENABLED, config.analyzers.dartEnabled)
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
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_SKIP_DEV, config.analyzers.composerSkipDev)
        settings.setBooleanIfNotNull(ANALYZER_CPANFILE_ENABLED, config.analyzers.cpanEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUGETCONF_ENABLED, config.analyzers.nugetconfEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, select(config.analyzers.nodePackage.enabled, config.analyzers.nodeEnabled))
        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_SKIPDEV, config.analyzers.nodePackage.skipDevDependencies)
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, select(config.analyzers.nodeAudit.enabled, config.analyzers.nodeAuditEnabled))
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_USE_CACHE, config.analyzers.nodeAudit.useCache)
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_SKIPDEV, config.analyzers.nodeAudit.skipDevDependencies)
        settings.setStringIfNotEmpty(ANALYZER_NODE_AUDIT_URL, config.analyzers.nodeAudit.url)
        settings.setBooleanIfNotNull(ANALYZER_YARN_AUDIT_ENABLED, config.analyzers.nodeAudit.yarnEnabled)
        settings.setStringIfNotNull(ANALYZER_YARN_PATH, config.analyzers.nodeAudit.yarnPath);
        settings.setBooleanIfNotNull(ANALYZER_PNPM_AUDIT_ENABLED, config.analyzers.nodeAudit.pnpmEnabled)
        settings.setStringIfNotNull(ANALYZER_PNPM_PATH, config.analyzers.nodeAudit.pnpmPath);
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

        Downloader.getInstance().configure(settings);
    }

    private void configureSlack(Settings settings) {
        settings.setBooleanIfNotNull(SlackNotificationSenderService.SLACK__WEBHOOK__ENABLED, config.slack.enabled)
        settings.setStringIfNotEmpty(SlackNotificationSenderService.SLACK__WEBHOOK__URL, config.slack.webhookUrl)
    }

    private void configureProxy(Settings settings) {
        String proxyHost = System.getProperty("https.proxyHost", System.getProperty("http.proxyHost"))
        if (!Strings.isNullOrEmpty(proxyHost)) {
            String proxyPort = System.getProperty("https.proxyPort", System.getProperty("http.proxyPort"))
            String nonProxyHosts = System.getProperty("https.nonProxyHosts", System.getProperty("http.nonProxyHosts"))
            String proxyUser = System.getProperty("https.proxyUser", System.getProperty("http.proxyUser"))
            String proxyPassword = System.getProperty("https.proxyPassword", System.getProperty("http.proxyPassword"))
            config.proxy.server = proxyHost
            try {
                config.proxy.port = Integer.parseInt(proxyPort)
            } catch (NumberFormatException nfe) {
                logger.warn("Unable to convert the configured `http.proxyPort` to a number: ${proxyPort}");
            }
            if (!Strings.isNullOrEmpty(proxyUser)) {
                config.proxy.username = proxyUser
            }
            if (!Strings.isNullOrEmpty(proxyPassword)) {
                config.proxy.password = proxyPassword
            }
            if (!Strings.isNullOrEmpty(nonProxyHosts)) {
                config.proxy.nonProxyHosts = nonProxyHosts.tokenize("|")
            }
        }
        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        settings.setStringIfNotEmpty(PROXY_NON_PROXY_HOSTS, config.proxy.nonProxyHosts.join("|"))
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions(Collection<String> suppressionFiles, String suppressionFile) {
        List<String> files = []
        if (suppressionFiles != null) {
            for (String sf : suppressionFiles) {
                files.add(sf.toString())
            }
        }
        if (suppressionFile != null) {
            files.add(suppressionFile)
        }
        return files.toArray(new String[0])
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

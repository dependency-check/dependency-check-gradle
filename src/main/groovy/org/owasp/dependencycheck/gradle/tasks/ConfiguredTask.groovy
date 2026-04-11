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
import groovy.transform.CompileStatic
import org.gradle.api.DefaultTask
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Internal
import org.owasp.dependencycheck.gradle.extension.DataExtension
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.extension.NvdExtension
import org.owasp.dependencycheck.gradle.extension.ProxyExtension
import org.owasp.dependencycheck.utils.Settings

import javax.inject.Inject

import static org.owasp.dependencycheck.utils.Settings.KEYS.*

/**
 * Standard class to read in the configuration and populated the ODC settings.
 *
 * @author Jeremy Long
 */
@CompileStatic
abstract class ConfiguredTask extends DefaultTask {

    @Internal
    DependencyCheckExtension defaults
    @Internal
    Settings settings
    @Internal
    String PROPERTIES_FILE = 'task.properties'

    @Internal
    final Property<Boolean> autoUpdate
    @Internal
    final Property<Boolean> failOnError
    @Internal
    final Property<Boolean> quickQueryTimestamp

    @Internal
    ProxyExtension proxy
    @Internal
    NvdExtension nvd
    @Internal
    DataExtension data

    @Inject
    ConfiguredTask(ObjectFactory objects) {
        def defaults = (DependencyCheckExtension) project.getExtensions().findByName('dependencyCheck')
        this.defaults = defaults

        this.autoUpdate = objects.property(Boolean)
        this.autoUpdate.convention(defaults.autoUpdate)

        this.failOnError = objects.property(Boolean)
        this.failOnError.convention(defaults.failOnError)

        this.quickQueryTimestamp = objects.property(Boolean)
        this.quickQueryTimestamp.convention(defaults.quickQueryTimestamp)

        this.proxy = objects.newInstance(ProxyExtension, objects)
        proxy.server.convention(defaults.proxy.server)
        proxy.port.convention(defaults.proxy.port)
        proxy.username.convention(defaults.proxy.username)
        proxy.password.convention(defaults.proxy.password)
        proxy.nonProxyHosts.convention(defaults.proxy.nonProxyHosts)

        this.nvd = objects.newInstance(NvdExtension, objects)
        nvd.apiKey.convention(defaults.nvd.apiKey)
        nvd.endpoint.convention(defaults.nvd.endpoint)
        nvd.delay.convention(defaults.nvd.delay)
        nvd.resultsPerPage.convention(defaults.nvd.resultsPerPage)
        nvd.maxRetryCount.convention(defaults.nvd.maxRetryCount)
        nvd.validForHours.convention(defaults.nvd.validForHours)
        nvd.datafeedUrl.convention(defaults.nvd.datafeedUrl)
        nvd.datafeedUser.convention(defaults.nvd.datafeedUser)
        nvd.datafeedPassword.convention(defaults.nvd.datafeedPassword)
        nvd.datafeedBearerToken.convention(defaults.nvd.datafeedBearerToken)
        nvd.datafeedStartYear.convention(defaults.nvd.datafeedStartYear)

        this.data = objects.newInstance(DataExtension, objects, project)
        data.directory.convention(defaults.data.directory)
        data.connectionString.convention(defaults.data.connectionString)
        data.username.convention(defaults.data.username)
        data.password.convention(defaults.data.password)
        data.driver.convention(defaults.data.driver)
        data.driverPath.convention(defaults.data.driverPath)
    }

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
        settings.setBooleanIfNotNull(AUTO_UPDATE, autoUpdate.getOrNull())
        configureProxy(settings)
        settings.setStringIfNotNull(DATA_DIRECTORY, data.directory.getOrNull())
        settings.setStringIfNotEmpty(DB_DRIVER_NAME, data.driver.getOrNull())
        settings.setStringIfNotEmpty(DB_DRIVER_PATH, data.driverPath.getOrNull())
        settings.setStringIfNotEmpty(DB_CONNECTION_STRING, data.connectionString.getOrNull())
        settings.setStringIfNotEmpty(DB_USER, data.username.getOrNull())
        settings.setStringIfNotEmpty(DB_PASSWORD, data.password.getOrNull())
        settings.setStringIfNotEmpty(NVD_API_KEY, nvd.apiKey.getOrNull())
        settings.setStringIfNotEmpty(NVD_API_ENDPOINT, nvd.endpoint.getOrNull())
        settings.setIntIfNotNull(NVD_API_DELAY, nvd.delay.getOrNull())
        settings.setIntIfNotNull(NVD_API_RESULTS_PER_PAGE, nvd.resultsPerPage.getOrNull())
        settings.setIntIfNotNull(NVD_API_MAX_RETRY_COUNT, nvd.maxRetryCount.getOrNull())
        settings.setIntIfNotNull(NVD_API_VALID_FOR_HOURS, nvd.validForHours.getOrNull())
        settings.setStringIfNotEmpty(NVD_API_DATAFEED_URL, nvd.datafeedUrl.getOrNull())
        if (nvd.datafeedUser.getOrNull() && nvd.datafeedPassword.getOrNull()) {
            settings.setStringIfNotEmpty(NVD_API_DATAFEED_USER, nvd.datafeedUser.getOrNull())
            settings.setStringIfNotEmpty(NVD_API_DATAFEED_PASSWORD, nvd.datafeedPassword.getOrNull())
        }
        settings.setStringIfNotEmpty(NVD_API_DATAFEED_BEARER_TOKEN, nvd.datafeedBearerToken.getOrNull())
        settings.setIntIfNotNull(NVD_API_DATAFEED_START_YEAR, nvd.datafeedStartYear.getOrNull())
    }

    private void configureProxy(Settings settings) {
        String proxyServer = proxy.server.getOrNull()
        Integer proxyPort = proxy.port.getOrNull()
        String proxyUser = proxy.username.getOrNull()
        String proxyPass = proxy.password.getOrNull()
        List<String> nonProxyHostsList = proxy.nonProxyHosts.getOrElse([])

        // Fall back to system properties if not configured
        String sysProxyHost = System.getProperty("https.proxyHost", System.getProperty("http.proxyHost"))
        if (!Strings.isNullOrEmpty(sysProxyHost) && proxyServer == null) {
            proxyServer = sysProxyHost
            String sysProxyPort = System.getProperty("https.proxyPort", System.getProperty("http.proxyPort"))
            if (sysProxyPort != null) {
                try {
                    proxyPort = Integer.parseInt(sysProxyPort)
                } catch (NumberFormatException nfe) {
                    logger.warn("Unable to convert the configured `http.proxyPort` to a number: ${sysProxyPort}")
                }
            }
            String sysProxyUser = System.getProperty("https.proxyUser", System.getProperty("http.proxyUser"))
            if (!Strings.isNullOrEmpty(sysProxyUser)) {
                proxyUser = sysProxyUser
            }
            String sysProxyPassword = System.getProperty("https.proxyPassword", System.getProperty("http.proxyPassword"))
            if (!Strings.isNullOrEmpty(sysProxyPassword)) {
                proxyPass = sysProxyPassword
            }
            String sysNonProxyHosts = System.getProperty("https.nonProxyHosts", System.getProperty("http.nonProxyHosts"))
            if (!Strings.isNullOrEmpty(sysNonProxyHosts)) {
                nonProxyHostsList = sysNonProxyHosts.tokenize("|")
            }
        }

        settings.setStringIfNotEmpty(PROXY_SERVER, proxyServer)
        settings.setStringIfNotEmpty(PROXY_PORT, proxyPort?.toString())
        settings.setStringIfNotEmpty(PROXY_USERNAME, proxyUser)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, proxyPass)
        settings.setStringIfNotEmpty(PROXY_NON_PROXY_HOSTS, nonProxyHostsList ? nonProxyHostsList.join("|") : null)
    }
}

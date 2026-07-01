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
 * Copyright (c) 2015 Sion Williams. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle

import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.testfixtures.ProjectBuilder
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.extension.NexusExtension
import org.owasp.dependencycheck.gradle.extension.OssIndexExtension
import org.owasp.dependencycheck.utils.Settings
import spock.lang.Specification

import java.time.Duration

import static org.owasp.dependencycheck.utils.Settings.KEYS.*

@SuppressWarnings('ConfigurationAvoidance')
class DependencyCheckGradlePluginSpec extends Specification {
    static final String PLUGIN_ID = 'org.owasp.dependencycheck'
    Project project

    def setup() {
        project = ProjectBuilder.builder().build()
        project.apply plugin: PLUGIN_ID
    }

    def 'dependencyCheck extension exists'() {
        expect:
        project.extensions.findByName('dependencyCheck')
    }

    def 'dependencyCheck extension has correct default data configuration'() {
        setup:
        DependencyCheckExtension extension = project.extensions.findByName('dependencyCheck') as DependencyCheckExtension

        expect:
        extension.data.directory.get() == "${project.gradle.gradleUserHomeDir}/dependency-check-data/11.0"
    }

    def "dependencyCheckAnalyze task exists"() {
        expect:
        project.tasks.findByName(DependencyCheckPlugin.ANALYZE_TASK)
    }

    def "dependencyCheckAggregate task exists"() {
        expect:
        project.tasks.findByName(DependencyCheckPlugin.AGGREGATE_TASK)
    }

    def "dependencyCheckPurge task exists"() {
        expect:
        project.tasks.findByName(DependencyCheckPlugin.PURGE_TASK)
    }

    def "dependencyCheckUpdate task exists"() {
        expect:
        project.tasks.findByName(DependencyCheckPlugin.UPDATE_TASK)
    }

    def 'dependencyCheck task has correct default values'() {
        setup:
        Task task = project.tasks.findByName(DependencyCheckPlugin.ANALYZE_TASK)

        expect:
        task.group == 'OWASP dependency-check'
        task.description == 'Identifies and reports known vulnerabilities (CVEs) in project dependencies.'

        with(project.dependencyCheck as DependencyCheckExtension) {
            proxy.server.getOrNull() == null
            proxy.port.getOrNull() == null
            proxy.username.getOrNull() == null
            proxy.password.getOrNull() == null
            nvd.apiKey.getOrNull() == null
            nvd.delay.getOrNull() == null
            nvd.maxRetryCount.getOrNull() == null
            outputDirectory.get().asFile == project.layout.buildDirectory.dir('reports').get().asFile
            scanConfigurations.get() == []
            skipConfigurations.get() == []
            scanProjects.get() == []
            skipProjects.get() == []
            skipGroups.get() == []
            skipTestGroups.get() == true
            suppressionFile.getOrNull() == null
            connectionTimeout.getOrNull() == null
            readTimeout.getOrNull() == null
        }
    }

    def 'tasks use correct values when extension is used'() {
        given:
        def slackWebhookUrl = 'https://slack.com/webhook'
        when:
        project.getExtensions().findByType(DependencyCheckExtension).with {
            proxy.server = '127.0.0.1'
            proxy.port = 3128
            proxy.username = 'proxyUsername'
            proxy.password = 'proxyPassword'
            proxy.nonProxyHosts = ['localhost']

            nvd.apiKey = 'apiKey'
            nvd.delay = 5000
            nvd.maxRetryCount = 20

            connectionTimeout = 3000L
            readTimeout = Duration.ofMinutes(2)

            hostedSuppressions.url = 'suppressionsurl'
            hostedSuppressions.validForHours = 5
            hostedSuppressions.forceupdate = true

            slack.enabled = true
            slack.webhookUrl = slackWebhookUrl

            analyzers.artifactory.enabled = true
            analyzers.artifactory.url = 'https://example.com/artifacgtory'
            analyzers.artifactory.bearerToken = 'abc123=='
            analyzers.kev.enabled = false
            analyzers.kev.url = "https://example.com"
            analyzers.kev.validForHours = 12
            analyzers.retirejs.filters = ['filter1', 'filter2']
            analyzers.retirejs.filterNonVulnerable = true

            outputDirectory = 'outputDirectory'

            scanConfigurations = ['a']
            skipConfigurations = ['b']
            scanProjects = ['a']
            skipProjects = ['b']
            skipGroups = ['b']
            skipTestGroups = false

            suppressionFile = './src/config/suppression.xml'
            suppressionFiles = ['./src/config/suppression1.xml', './src/config/suppression2.xml']
            suppressionFileUser = 'suppressionFileUsername'
            suppressionFilePassword = 'suppressionFilePassword'

            additionalCpes {
                additional1 {
                    description = "Additional1"
                    cpe = "cpe:2.3:a:aGroup1:aPackage1:123:*:*:*:*:*:*:*"
                }

                additional2 {
                    description = "Additional2"
                    cpe = "cpe:2.3:a:aGroup2:aPackage2:123:*:*:*:*:*:*:*"
                }

                additional3 {
                    description = "Additional3"
                    cpe = "cpe:2.3:a:aGroup3:aPackage3:123:*:*:*:*:*:*:*"
                }
            }
        }

        then:
        with(project.dependencyCheck as DependencyCheckExtension) {
            proxy.server.get() == '127.0.0.1'
            proxy.port.get() == 3128
            proxy.username.get() == 'proxyUsername'
            proxy.password.get() == 'proxyPassword'
            proxy.nonProxyHosts.get() == ['localhost']

            connectionTimeout.get() == Duration.ofMillis(3000)
            readTimeout.get() == Duration.ofMinutes(2)

            nvd.apiKey.get() == 'apiKey'
            nvd.delay.get() == 5000
            nvd.maxRetryCount.get() == 20
            hostedSuppressions.url.get() == 'suppressionsurl'
            hostedSuppressions.validForHours.get() == 5
            hostedSuppressions.forceupdate.get() == true
            outputDirectory.get().asFile == project.file('outputDirectory')
            scanConfigurations.get() == ['a']
            skipConfigurations.get() == ['b']
            scanProjects.get() == ['a']
            skipProjects.get() == ['b']
            skipGroups.get() == ['b']
            skipTestGroups.get() == false
            suppressionFile.get() == './src/config/suppression.xml'
            suppressionFiles.get().getAt(0) == './src/config/suppression1.xml'
            suppressionFiles.get().getAt(1) == './src/config/suppression2.xml'
            //suppressionFiles == ['./src/config/suppression1.xml', './src/config/suppression2.xml']
            suppressionFileUser.get() == 'suppressionFileUsername'
            suppressionFilePassword.get() == 'suppressionFilePassword'
            analyzers.artifactory.enabled.get() == true
            analyzers.artifactory.url.get() == 'https://example.com/artifacgtory'
            analyzers.artifactory.bearerToken.get() == 'abc123=='
            analyzers.kev.enabled.get() == false
            analyzers.kev.url.get() == "https://example.com"
            analyzers.retirejs.filters.get() == ['filter1', 'filter2']
            analyzers.retirejs.filterNonVulnerable.get() == true
            slack.enabled.get() == true
            slack.webhookUrl.get() == slackWebhookUrl
            additionalCpes.size() == 3
            additionalCpes.getByName('additional1').description.get() == 'Additional1'
            additionalCpes.getByName('additional1').cpe.get() == 'cpe:2.3:a:aGroup1:aPackage1:123:*:*:*:*:*:*:*'
        }
    }

    def 'legacy nexus properties mapped to NexusExtension'() {
        given:
        project.dependencyCheck {
            analyzers.nexusEnabled = enabled
            analyzers.nexusUrl = url
            analyzers.nexusUsesProxy = proxy
        }

        expect:
        project.dependencyCheck {
            assert analyzers.nexus.enabled.get() == enabled
            assert analyzers.nexus.url.get() == url
            assert analyzers.nexus.usesProxy.get() == proxy
        }

        where:
        enabled | url | proxy
        true | 'http://someurl' | true
        false | 'https://testurl' | false
    }

    def 'NexusExtension properties configure task settings'() {
        given:
        def task = project.tasks.findByName(taskName)
        with(project.dependencyCheck.analyzers.nexus as NexusExtension) {
            enabled.set(true)
            usesProxy.set(true)
            url.set('https://nexus')
            username.set('user')
            password.set('pass')
        }

        when:
        task.initializeSettings()

        then:
        with(task.settings as Settings) {
            getBoolean(ANALYZER_NEXUS_ENABLED)
            getBoolean(ANALYZER_NEXUS_USES_PROXY)
            getString(ANALYZER_NEXUS_URL) == 'https://nexus'
            getString(ANALYZER_NEXUS_USER) == 'user'
            getString(ANALYZER_NEXUS_PASSWORD) == 'pass'
        }

        where:
        taskName | _
        DependencyCheckPlugin.ANALYZE_TASK | _
        DependencyCheckPlugin.AGGREGATE_TASK | _
    }

    def 'OssIndexExtension properties configure task settings'() {
        given:
        def task = project.tasks.findByName(taskName)
        with(project.dependencyCheck.analyzers.ossIndex as OssIndexExtension) {
            enabled.set(true)
            url.set('https://ossindex')
            username.set('user')
            password.set('pass')
            validForHours.set(48)
            warnOnlyOnRemoteErrors.set(true)
        }

        when:
        task.initializeSettings()

        then:
        with(task.settings as Settings) {
            getBoolean(ANALYZER_OSSINDEX_ENABLED)
            getString(ANALYZER_OSSINDEX_URL) == 'https://ossindex'
            getString(ANALYZER_OSSINDEX_USER) == 'user'
            getString(ANALYZER_OSSINDEX_PASSWORD) == 'pass'
            getInt(ANALYZER_OSSINDEX_CACHE_VALID_FOR_HOURS) == 48
            getBoolean(ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS)
        }

        where:
        taskName | _
        DependencyCheckPlugin.ANALYZE_TASK | _
        DependencyCheckPlugin.AGGREGATE_TASK | _
    }

    def 'scanConfigurations and skipConfigurations are mutually exclusive'() {
        when:
        project.dependencyCheck {
            scanConfigurations = ['a']
            skipConfigurations = ['b']
        }
        task = project.tasks.findByName(DependencyCheckPlugin.ANALYZE_TASK).analyze()

        then:
        thrown(IllegalArgumentException)
    }

    def 'scanProjects and skipProjects are mutually exclusive'() {
        when:
        project.dependencyCheck {
            scanProjects = ['a']
            skipProjects = ['b']
        }
        task = project.tasks.findByName(DependencyCheckPlugin.AGGREGATE_TASK).analyze()

        then:
        thrown(IllegalArgumentException)
    }
}

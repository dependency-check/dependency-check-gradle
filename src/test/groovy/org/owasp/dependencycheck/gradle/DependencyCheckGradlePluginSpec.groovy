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
import spock.lang.Specification

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
        extension.data.directory == "${project.gradle.gradleUserHomeDir}/dependency-check-data/7.0"
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

        project.dependencyCheck.proxy.server == null
        project.dependencyCheck.proxy.port == null
        project.dependencyCheck.proxy.username == null
        project.dependencyCheck.proxy.password == null
        project.dependencyCheck.cve.urlModified == null
        project.dependencyCheck.cve.urlBase == null
        project.dependencyCheck.outputDirectory == "${project.buildDir}/reports"
        project.dependencyCheck.quickQueryTimestamp == null
        project.dependencyCheck.scanConfigurations == []
        project.dependencyCheck.skipConfigurations == []
        project.dependencyCheck.scanProjects == []
        project.dependencyCheck.skipProjects == []
        project.dependencyCheck.skipGroups == []
        project.dependencyCheck.skipTestGroups == true
        project.dependencyCheck.suppressionFile == null
    }

    def 'tasks use correct values when extension is used'() {
        given:
        def slackWebhookUrl = 'https://slack.com/webhook'
        when:
        project.dependencyCheck {
            proxy {
                server = '127.0.0.1'
                port = 3128
                username = 'proxyUsername'
                password = 'proxyPassword'
                nonProxyHosts = ['localhost']
            }
            cve {
                urlBase = 'urlBase'
                urlModified = 'urlModified'
            }

            hostedSuppressions {
                url = 'suppressionsurl'
                validForHours = 5
                forceupdate = true
            }

            slack {
                enabled = true
                webhookUrl = slackWebhookUrl
            }

            analyzers {
                artifactory {
                    enabled = true
                    url = 'https://example.com/artifacgtory'
                    bearerToken = 'abc123=='
                }
                knownExploitedEnabled = false
                retirejs {
                    filters = ['filter1', 'filter2']
                    filterNonVulnerable = true
                }
            }

            outputDirectory = 'outputDirectory'
            quickQueryTimestamp = false

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
        }

        then:
        project.dependencyCheck.proxy.server == '127.0.0.1'
        project.dependencyCheck.proxy.port == 3128
        project.dependencyCheck.proxy.username == 'proxyUsername'
        project.dependencyCheck.proxy.password == 'proxyPassword'
        project.dependencyCheck.proxy.nonProxyHosts == ['localhost']

        project.dependencyCheck.cve.urlModified == 'urlModified'
        project.dependencyCheck.cve.urlBase == 'urlBase'
        project.dependencyCheck.hostedSuppressions.url == 'suppressionsurl'
        project.dependencyCheck.hostedSuppressions.validForHours == 5
        project.dependencyCheck.hostedSuppressions.forceupdate == true
        project.dependencyCheck.outputDirectory == 'outputDirectory'
        project.dependencyCheck.quickQueryTimestamp == false
        project.dependencyCheck.scanConfigurations == ['a']
        project.dependencyCheck.skipConfigurations == ['b']
        project.dependencyCheck.scanProjects == ['a']
        project.dependencyCheck.skipProjects == ['b']
        project.dependencyCheck.skipGroups == ['b']
        project.dependencyCheck.skipTestGroups == false
        project.dependencyCheck.suppressionFile == './src/config/suppression.xml'
        project.dependencyCheck.suppressionFiles.getAt(0) == './src/config/suppression2.xml'
        project.dependencyCheck.suppressionFiles.getAt(1) == './src/config/suppression1.xml'
        //project.dependencyCheck.suppressionFiles == ['./src/config/suppression1.xml', './src/config/suppression2.xml']
        project.dependencyCheck.suppressionFileUser == 'suppressionFileUsername'
        project.dependencyCheck.suppressionFilePassword == 'suppressionFilePassword'
        project.dependencyCheck.analyzers.artifactory.enabled == true
        project.dependencyCheck.analyzers.artifactory.url == 'https://example.com/artifacgtory'
        project.dependencyCheck.analyzers.artifactory.bearerToken == 'abc123=='
        project.dependencyCheck.analyzers.knownExploitedEnabled == false
        project.dependencyCheck.analyzers.retirejs.filters == ['filter1', 'filter2']
        project.dependencyCheck.analyzers.retirejs.filterNonVulnerable == true
        project.dependencyCheck.slack.enabled == true
        project.dependencyCheck.slack.webhookUrl == slackWebhookUrl
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

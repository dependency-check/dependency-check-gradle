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

import org.gradle.api.Task
import org.gradle.api.Project
import org.gradle.testfixtures.ProjectBuilder
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
        project.dependencyCheck.cve.url12Modified == null
        project.dependencyCheck.cve.url20Modified == null
        project.dependencyCheck.cve.url12Base == null
        project.dependencyCheck.cve.url20Base == null
        project.dependencyCheck.outputDirectory == "${project.buildDir}/reports"
        project.dependencyCheck.quickQueryTimestamp == null
        project.dependencyCheck.scanConfigurations == []
        project.dependencyCheck.skipConfigurations == []
        project.dependencyCheck.skipTestGroups == true
        project.dependencyCheck.suppressionFile == null
    }

    def 'tasks use correct values when extension is used'() {
        when:
        project.dependencyCheck {
            proxy {
                server = '127.0.0.1'
                port = 3128
                username = 'proxyUsername'
                password = 'proxyPassword'
            }

            cve {
                url12Base = 'cveUrl12Base'
                url20Base = 'cveUrl20Base'
                url12Modified = 'cveUrl12Modified'
                url20Modified = 'cveUrl20Modified'
            }

            analyzers {
                artifactory {
                    url = 'https://example.com/artifacgtory'
                    bearerToken = 'abc123=='
                }

                retirejs {
                    filters = ['filter1', 'filter2']
                    filterNonVulnerable = true
                }
            }

            outputDirectory = 'outputDirectory'
            quickQueryTimestamp = false

            scanConfigurations = ['a']
            skipConfigurations = ['b']
            skipTestGroups = false

            suppressionFile = './src/config/suppression.xml'
            suppressionFiles = ['./src/config/suppression1.xml', './src/config/suppression2.xml']
        }

        then:
        project.dependencyCheck.proxy.server == '127.0.0.1'
        project.dependencyCheck.proxy.port == 3128
        project.dependencyCheck.proxy.username == 'proxyUsername'
        project.dependencyCheck.proxy.password == 'proxyPassword'
        project.dependencyCheck.cve.url12Modified == 'cveUrl12Modified'
        project.dependencyCheck.cve.url20Modified == 'cveUrl20Modified'
        project.dependencyCheck.cve.url12Base == 'cveUrl12Base'
        project.dependencyCheck.cve.url20Base == 'cveUrl20Base'
        project.dependencyCheck.outputDirectory == 'outputDirectory'
        project.dependencyCheck.quickQueryTimestamp == false
        project.dependencyCheck.scanConfigurations == ['a']
        project.dependencyCheck.skipConfigurations == ['b']
        project.dependencyCheck.skipTestGroups == false
        project.dependencyCheck.suppressionFile == './src/config/suppression.xml'
        project.dependencyCheck.suppressionFiles == ['./src/config/suppression1.xml', './src/config/suppression2.xml']
        project.dependencyCheck.analyzers.artifactory.url == 'https://example.com/artifacgtory'
        project.dependencyCheck.analyzers.artifactory.bearerToken == 'abc123=='
        project.dependencyCheck.analyzers.retirejs.filters == ['filter1', 'filter2']
        project.dependencyCheck.analyzers.retirejs.filterNonVulnerable == true
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
}

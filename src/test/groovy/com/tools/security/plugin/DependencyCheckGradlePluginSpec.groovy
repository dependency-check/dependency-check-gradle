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

package com.tools.security.plugin

import nebula.test.PluginProjectSpec
import org.gradle.api.Task

class DependencyCheckGradlePluginSpec extends PluginProjectSpec {
    static final String PLUGIN_ID = 'dependency-check-gradle'

    @Override
    String getPluginName() {
        return PLUGIN_ID
    }

    def setup() {
        project.apply plugin: pluginName
    }

    def 'apply creates dependencyCheck extension'() {
        expect: project.extensions.findByName( 'dependencyCheck' )
    }

    def "apply creates dependencyCheck task"() {
        expect: project.tasks.findByName( 'dependencyCheck' )
    }

    def 'dependencyCheck task has correct default values'() {
        setup:
        Task task = project.tasks.findByName( 'dependencyCheck' )

        expect:
        task.group == 'Dependency Check'
        task.description == 'Produce dependency security report.'
        project.dependencyCheck.proxy.server == null
        project.dependencyCheck.proxy.port == null
        project.dependencyCheck.proxy.username == null
        project.dependencyCheck.proxy.password == null
        project.dependencyCheck.cve.url12Modified == null
        project.dependencyCheck.cve.url20Modified == null
        project.dependencyCheck.cve.startYear == null
        project.dependencyCheck.cve.url12Base == null
        project.dependencyCheck.cve.url20Base == null
        project.dependencyCheck.outputDirectory == './reports'
        project.dependencyCheck.quickQueryTimestamp == null
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
                startYear = 2002
                url12Base = 'cveUrl12Base'
                url20Base = 'cveUrl20Base'
                url12Modified = 'cveUrl12Modified'
                url20Modified = 'cveUrl20Modified'
            }

            outputDirectory = 'outputDirectory'
            quickQueryTimestamp = false
        }

        then:
        project.dependencyCheck.proxy.server == '127.0.0.1'
        project.dependencyCheck.proxy.port == 3128
        project.dependencyCheck.proxy.username == 'proxyUsername'
        project.dependencyCheck.proxy.password == 'proxyPassword'
        project.dependencyCheck.cve.url12Modified == 'cveUrl12Modified'
        project.dependencyCheck.cve.url20Modified == 'cveUrl20Modified'
        project.dependencyCheck.cve.startYear == 2002
        project.dependencyCheck.cve.url12Base == 'cveUrl12Base'
        project.dependencyCheck.cve.url20Base == 'cveUrl20Base'
        project.dependencyCheck.outputDirectory == 'outputDirectory'
        project.dependencyCheck.quickQueryTimestamp == false
    }
}

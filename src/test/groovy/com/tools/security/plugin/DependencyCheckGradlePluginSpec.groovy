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
    static final String PLUGIN_ID = 'dependency-check'

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
        task.proxyServer == null
        task.proxyPort == null
        task.proxyUsername == ''
        task.proxyPassword == ''
        task.cveUrl12Modified == 'https://nvd.nist.gov/download/nvdcve-Modified.xml.gz'
        task.cveUrl20Modified == 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz'
        task.cveStartYear == 2002
        task.cveUrl12Base == 'https://nvd.nist.gov/download/nvdcve-%d.xml.gz'
        task.cveUrl20Base == 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz'
        task.outputDirectory == './reports'
        task.quickQueryTimestamp == true
    }

    def 'tasks use correct values when extension is used'() {
        when:
        project.dependencyCheck {
            proxyServer = '127.0.0.1'
            proxyPort = 3128
            proxyUsername = 'proxyUsername'
            proxyPassword = 'proxyPassword'
            cveUrl12Modified = 'cveUrl12Modified'
            cveUrl20Modified = 'cveUrl20Modified'
            cveStartYear = 2002
            cveUrl12Base = 'cveUrl12Base'
            cveUrl20Base = 'cveUrl20Base'
            outputDirectory = 'outputDirectory'
            quickQueryTimestamp = false
        }

        then:
        Task task = project.tasks.findByName( 'dependencyCheck' )
        task.proxyServer == '127.0.0.1'
        task.proxyPort == 3128
        task.proxyUsername == 'proxyUsername'
        task.proxyPassword == 'proxyPassword'
        task.cveUrl12Modified == 'cveUrl12Modified'
        task.cveUrl20Modified == 'cveUrl20Modified'
        task.cveStartYear == 2002
        task.cveUrl12Base == 'cveUrl12Base'
        task.cveUrl20Base == 'cveUrl20Base'
        task.outputDirectory == 'outputDirectory'
        task.quickQueryTimestamp == false
    }
}

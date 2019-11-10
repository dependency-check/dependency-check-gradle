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
package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.Project

/**
 * The analyzer configuration extension. Any value not configured will use the dependency-check-core defaults.
 */
class AnalyzerExtension {

    AnalyzerExtension(Project project) {
        this.project = project;
    }

    Project project;

    /**
     * Sets whether the experimental analyzers will be used.
     */
    Boolean experimentalEnabled
    /**
     * Sets whether the Archive Analyzer will be used.
     */
    Boolean archiveEnabled
    /**
     * A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed.
     */
    String zipExtensions
    /**
     * Sets whether Jar Analyzer will be used.
     */
    Boolean jarEnabled
    /**
     * Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below).
     */
    Boolean centralEnabled
    /**
     * Sets whether Nexus Analyzer will be used. This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation.
     */
    Boolean nexusEnabled
    /**
     * Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled.
     */
    String nexusUrl
    /**
     * Whether or not the defined proxy should be used when connecting to Nexus.
     */
    Boolean nexusUsesProxy
    /**
     * Sets whether or not the .NET Nuget Nuspec Analyzer will be used.
     */
    Boolean nuspecEnabled
    /**
     * Sets whether or not the .NET Assembly Analyzer should be used.
     */
    Boolean assemblyEnabled
    /**
     * The path to dotnet core - used to analyze dot net assemblies.
     */
    String pathToDotnet
    /**
     * Sets whether the Golang Dependency analyzer is enabled. Default is true.
     */
    Boolean golangDepEnabled
    /**
     * Sets whether Golang Module Analyzer is enabled; this requires `go` to be
     * installed. Default is true.
     */
    Boolean golangModEnabled
    /**
     * The path to `go` - used to analyze go modules via `go mod`.
     */
    String pathToGo
    /**
     * Sets whether or not the cocoapods analyzer is enabled.
     */
    Boolean cocoapodsEnabled
    /**
     * Sets whether or not the swift package manager is enabled.
     */
    Boolean swiftEnabled

    /**
     * Sets whether or not the Ruby Bundle Audit analyzer is enabled; requires running bundle audit.
     */
    Boolean bundleAuditEnabled
    /**
     * The path to Ruby's bundle audit.
     */
    String pathToBundleAudit
    /**
     * Sets whether the Python Distribution Analyzer will be used.
     */
    Boolean pyDistributionEnabled
    /**
     * Sets whether the Python Package Analyzer will be used.
     */
    Boolean pyPackageEnabled
    /**
     * Sets whether the Ruby Gemspec Analyzer will be used.
     */
    Boolean rubygemsEnabled
    /**
     * Sets whether or not the openssl Analyzer should be used.
     */
    Boolean opensslEnabled
    /**
     * Sets whether or not the CMake Analyzer should be used.
     */
    Boolean cmakeEnabled
    /**
     * Sets whether or not the autoconf Analyzer should be used.
     */
    Boolean autoconfEnabled
    /**
     * Sets whether or not the PHP Composer Lock File Analyzer should be used.
     */
    Boolean composerEnabled
    /**
     * Sets whether or not the Node.js Analyzer should be used.
     */
    Boolean nodeEnabled
    /**
     * Sets whether or not the NSP Analyzer should be used.
     */
    Boolean nodeAuditEnabled
    /**
     * Sets whether or not the Nuget packages.config Configuration Analyzer should be used.
     */
    Boolean nugetconfEnabled
    /**
     * Sets whether or not the OSS Index Analyzer should be used.
     * @deprecated As of the 5.0.1 - please use ossIndex { enabled = true }
     */
    @Deprecated
    Boolean ossIndexEnabled

    /**
     * The configuration extension for retirejs settings.
     */
    RetireJSExtension retirejs = new RetireJSExtension()

    /**
     * The configuration extension for artifactory settings.
     */
    ArtifactoryExtension artifactory = new ArtifactoryExtension()

    /**
     * The configuration extension for artifactory settings.
     */
    OssIndexExtension ossIndex = new OssIndexExtension()

    /**
     * Allows programmatic configuration of the retirejs extension
     * @param configClosure the closure to configure the retirejs extension
     * @return the retirejs extension
     */
    def retirejs(Closure configClosure) {
        return project.configure(retirejs, configClosure)
    }

    /**
     * Allows programmatic configuration of the artifactory extension
     * @param configClosure the closure to configure the artifactory extension
     * @return the artifactory extension
     */
    def artifactory(Closure configClosure) {
        return project.configure(artifactory, configClosure)
    }

    /**
     * Allows programmatic configuration of the ossIndex extension
     * @param configClosure the closure to configure the ossIndex extension
     * @return the ossIndex extension
     */
    def ossIndex(Closure configClosure) {
        return project.configure(ossIndex, configClosure)
    }
}

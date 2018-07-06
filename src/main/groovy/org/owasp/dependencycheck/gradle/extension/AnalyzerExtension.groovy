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

/**
 * The analyzer configuration extension. Any value not configured will use the dependency-check-core defaults.
 */
class AnalyzerExtension {
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
     * The path to Mono for .NET assembly analysis on non-windows systems.
     */
    String pathToMono
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
    Boolean nspEnabled
}

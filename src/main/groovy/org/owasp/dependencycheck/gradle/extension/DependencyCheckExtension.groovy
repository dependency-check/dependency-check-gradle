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
 * Copyright (c) 2015 Wei Ma. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.extension


import org.gradle.api.Project

import static org.owasp.dependencycheck.reporting.ReportGenerator.Format

/*
 * Configuration extension for the dependencyCheck plugin.
 *
 * @author Wei Ma
 * @author Jeremy Long
 */

class DependencyCheckExtension {

    DependencyCheckExtension(Project project) {
        this.project = project;
        outputDirectory = "${project.buildDir}/reports"
    }

    Project project;

    /**
     * The configuration extension for proxy settings.
     */
    ProxyExtension proxy = new ProxyExtension()
    /**
     * The configuration extension for proxy settings.
     */
    SlackExtension slack = new SlackExtension()

    /**
     * The configuration extension that defines the location of the NVD CVE data.
     */
    CveExtension cve = new CveExtension()

    /**
     * Whether the plugin should fail when errors occur.
     */
    Boolean failOnError = true
    /**
     * The configuration extension for data related configuration options.
     */
    DataExtension data = new DataExtension(project)

    /**
     * Set to false if the proxy does not support HEAD requests. The default is true.
     */
    Boolean quickQueryTimestamp
    /**
     * The number of hours to wait before checking for additional updates from the NVD.
     */
    Integer cveValidForHours
    /**
     * The directory where the reports will be written. Defaults to 'build/reports'.
     */
    String outputDirectory
    /**
     * Configuration for the analyzers.
     */
    AnalyzerExtension analyzers = new AnalyzerExtension(project)
    /**
     * The path to the suppression file.
     */
    String suppressionFile
    /**
     * The list of paths to suppression files.
     */
    List<String> suppressionFiles = []
    /**
     * The path to the hints file.
     */
    String hintsFile
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled.
     */
    Boolean autoUpdate

    //The following properties are not used via the settings object, instead
    // they are directly used by the check task.
    /**
     * When set to true configurations that are considered a test configuration will not be included in the analysis.
     * A configuration is considered a test configuration if and only if any of the following conditions holds:
     * <ul>
     *     <li>the name of the configuration or any of its parent configurations equals 'testCompile'</li>
     *     <li>the name of the configuration or any of its parent configurations equals 'androidTestCompile'</li>
     *     <li>the configuration name starts with 'test'</li>
     *     <li>the configuration name starts with 'androidTest'</li>
     * </ul>
     * The default value is true.
     */
    Boolean skipTestGroups = true
    /**
     * The report format to be generated (HTML, XML, CSV, JUNIT, SARIF, ALL). This configuration option has
     * no affect if using this within the Site plugin unless the externalReport is set to true.
     * The default is HTML.
     */
    Format format = Format.HTML
    /**
     * The list of formats to generate to report (HTML, XML, CSV, JUNIT, SARIF, ALL).
     */
    List<Format> formats = []
    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is
     * 11 which means since the CVSS scores are 0-10, by default the build will never fail.
     */
    Float failBuildOnCVSS = 11.0
    /**
     * Specifies the CVSS score that should be considered a failure when generating a JUNIT formatted report. The default
     * is 0.0 which means all identified vulnerabilities would be considered a failure.
     */
    Float junitFailOnCVSS = 0.0
    /**
     * Displays a summary of the findings. Defaults to true.
     */
    Boolean showSummary = true
    /**
     * Names of the configurations to scan.
     *
     * This is mutually exclusive with the skipConfigurations property.
     */
    List<String> scanConfigurations = []
    /**
     * Names of the configurations to skip when scanning.
     *
     * This is mutually exclusive with the scanConfigurations property.
     */
    List<String> skipConfigurations = []
    /**
     * Paths of the projects to scan.
     *
     * This is mutually exclusive with the skipProjects property.
     */
    List<String> scanProjects = []
    /**
     * Paths of the projects to skip when scanning.
     *
     * This is mutually exclusive with the scanProjects property.
     */
    List<String> skipProjects = []
    /**
     * Group prefixes of the modules to skip when scanning.
     *
     * The 'project' prefix can be used to skip all internal dependencies from multi-project build.
     */
    List<String> skipGroups = []
    /**
     * The artifact types that will be analyzed in the gradle build.
     */
    List<String> analyzedTypes = ['jar', 'aar', 'js', 'war', 'ear', 'zip']
    /**
     * Whether or not to skip the execution of dependency-check.
     */
    Boolean skip = false
    /**
     * A set of files or folders to scan.
     */
    List<File> scanSet

    /**
     * The configuration extension for cache settings.
     */
    CacheExtension cache = new CacheExtension()

    /**
     * Allows programmatic configuration of the proxy extension
     * @param configClosure the closure to configure the proxy extension
     * @return the proxy extension
     */
    def proxy(Closure configClosure) {
        return project.configure(proxy, configClosure)
    }

    /**
     * Allows programmatic configuration of the slack extension
     * @param configClosure the closure to configure the slack extension
     * @return the slack extension
     */
    def slack(Closure configClosure) {
        return project.configure(slack, configClosure)
    }

    /**
     * Allows programmatic configuration of the cve extension
     * @param configClosure the closure to configure the cve extension
     * @return the cve extension
     */
    def cve(Closure configClosure) {
        return project.configure(cve, configClosure)
    }

    /**
     * Allows programmatic configuration of the analyzer extension
     * @param configClosure the closure to configure the analyzers extension
     * @return the analyzers extension
     */
    def analyzers(Closure configClosure) {
        return project.configure(analyzers, configClosure)
    }

    /**
     * Allows programmatic configuration of the data extension
     * @param configClosure the closure to configure the data extension
     * @return the data extension
     */
    def data(Closure configClosure) {
        return project.configure(data, configClosure)
    }

    /**
     * Allows programmatic configuration of the cache extension
     * @param configClosure the closure to configure the cache extension
     * @return the cache extension
     */
    def cache(Closure configClosure) {
        return project.configure(cache, configClosure)
    }
}

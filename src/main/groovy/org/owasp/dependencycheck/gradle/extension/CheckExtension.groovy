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

import static org.owasp.dependencycheck.reporting.ReportGenerator.Format
import org.gradle.api.Project

/*
 * Configuration extension for the dependencyCheck plugin.
 *
 * @author Wei Ma
 * @author Jeremy Long
 */
class CheckExtension extends UpdateExtension {

    CheckExtension(Project project) {
        outputDirectory = "${project.buildDir}/reports"
    }
    /**
     * The directory where the reports will be written. Defaults to 'build/reports'.
     */
    String outputDirectory

    /**
     * Configuration for the analyzers.
     */
    AnalyzerExtension analyzerExtension

    /**
     * The path to the suppression file.
     */
    String suppressionFile

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
     * When set to true dependency groups that start with 'test' will not be included in the analysis.
     * The default value is true.
     */
    Boolean skipTestGroups = true
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This configuration option has
     * no affect if using this within the Site plugin unless the externalReport is set to true.
     * The default is HTML.
     */
    Format format = Format.HTML
    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is
     * 11 which means since the CVSS scores are 0-10, by default the build will never fail.
     */
    Float failBuildOnCVSS = 11.0
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
}

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

import org.gradle.api.Action
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional

import javax.inject.Inject
import java.util.stream.Collectors

import static org.owasp.dependencycheck.reporting.ReportGenerator.Format

/*
 * Configuration extension for the dependencyCheck plugin.
 *
 * @author Wei Ma
 * @author Jeremy Long
 */

@groovy.transform.CompileStatic
class DependencyCheckExtension {

    Project project;

    private final Property<Boolean> scanBuildEnv
    private final Property<Boolean> scanDependencies
    private final Property<Boolean> failOnError
    private final Property<Boolean> quickQueryTimestamp
    private final DirectoryProperty outputDirectory
    private final Property<String> suppressionFile
    private final ListProperty<String> suppressionFiles
    private final Property<String> suppressionFileUser
    private final Property<String> suppressionFilePassword
    private final Property<String> suppressionFileBearerToken
    private final Property<String> hintsFile
    private final Property<Boolean> autoUpdate
    private final Property<Boolean> skipTestGroups
    private final Property<String> format
    private final ListProperty<String> formats
    private final Property<Float> failBuildOnCVSS
    private final Property<Float> junitFailOnCVSS
    private final Property<Boolean> failBuildOnUnusedSuppressionRule
    private final Property<Boolean> showSummary
    private final ListProperty<String> scanConfigurations
    private final ListProperty<String> skipConfigurations
    private final ListProperty<String> scanProjects
    private final ListProperty<String> skipProjects
    private final ListProperty<String> skipGroups
    private final ListProperty<String> analyzedTypes
    private final Property<Boolean> skip
    private final ConfigurableFileCollection scanSet

    /**
     * The configuration extension for proxy settings.
     */
    ProxyExtension proxy
    /**
     * The configuration extension for slack notifications.
     */
    SlackExtension slack

    /**
     * The configuration extension that defines the location of the NVD CVE data.
     */
    NvdExtension nvd

    /**
     * The configuration extension that configures the hosted suppressions file.
     */
    HostedSuppressionsExtension hostedSuppressions

    /**
     * The configuration extension for data related configuration options.
     */
    DataExtension data

    /**
     * Configuration for the analyzers.
     */
    AnalyzerExtension analyzers

    /**
     * Additional CPE to be analyzed.
     */
    NamedDomainObjectContainer<AdditionalCpe> additionalCpes

    /**
     * The configuration extension for cache settings.
     */
    CacheExtension cache

    @Inject
    DependencyCheckExtension(Project project, ObjectFactory objects) {
        this.project = project;

        this.scanBuildEnv = objects.property(Boolean).convention(false)
        this.scanDependencies = objects.property(Boolean).convention(true)
        this.failOnError = objects.property(Boolean).convention(true)
        this.quickQueryTimestamp = objects.property(Boolean)
        this.outputDirectory = objects.directoryProperty().convention(project.layout.buildDirectory.dir("reports"))
        this.suppressionFile = objects.property(String)
        this.suppressionFiles = objects.listProperty(String).convention([])
        this.suppressionFileUser = objects.property(String)
        this.suppressionFilePassword = objects.property(String)
        this.suppressionFileBearerToken = objects.property(String)
        this.hintsFile = objects.property(String)
        this.autoUpdate = objects.property(Boolean)
        this.skipTestGroups = objects.property(Boolean).convention(true)
        this.format = objects.property(String).convention(Format.HTML.toString())
        this.formats = objects.listProperty(String).convention([])
        this.failBuildOnCVSS = objects.property(Float).convention(11.0f)
        this.junitFailOnCVSS = objects.property(Float).convention(0.0f)
        this.failBuildOnUnusedSuppressionRule = objects.property(Boolean).convention(false)
        this.showSummary = objects.property(Boolean).convention(true)
        this.scanConfigurations = objects.listProperty(String).convention([])
        this.skipConfigurations = objects.listProperty(String).convention([])
        this.scanProjects = objects.listProperty(String).convention([])
        this.skipProjects = objects.listProperty(String).convention([])
        this.skipGroups = objects.listProperty(String).convention([])
        this.analyzedTypes = objects.listProperty(String).convention(['jar', 'aar', 'js', 'war', 'ear', 'zip'])
        this.skip = objects.property(Boolean).convention(false)
        this.scanSet = objects.fileCollection()

        cache = objects.newInstance(CacheExtension, objects)
        slack = objects.newInstance(SlackExtension, objects)
        proxy = objects.newInstance(ProxyExtension, objects)
        nvd = objects.newInstance(NvdExtension, objects)
        hostedSuppressions = objects.newInstance(HostedSuppressionsExtension, objects)
        data = objects.newInstance(DataExtension, objects, project)
        analyzers = new AnalyzerExtension(project, objects)
        additionalCpes = project.objects.domainObjectContainer(AdditionalCpe.class)
    }

    /**
     * Whether the buildEnv should be analyzed.
     */
    @Input
    @Optional
    Property<Boolean> getScanBuildEnv() {
        return scanBuildEnv
    }

    void setScanBuildEnv(Boolean value) {
        scanBuildEnv.set(value)
    }

    /**
     * Whether the dependencies should be analyzed.
     */
    @Input
    @Optional
    Property<Boolean> getScanDependencies() {
        return scanDependencies
    }

    void setScanDependencies(Boolean value) {
        scanDependencies.set(value)
    }

    /**
     * Whether the plugin should fail when errors occur.
     */
    @Input
    @Optional
    Property<Boolean> getFailOnError() {
        return failOnError
    }

    void setFailOnError(Boolean value) {
        failOnError.set(value)
    }

    /**
     * Set to false if the proxy does not support HEAD requests. The default is true.
     */
    @Input
    @Optional
    Property<Boolean> getQuickQueryTimestamp() {
        return quickQueryTimestamp
    }

    void setQuickQueryTimestamp(Boolean value) {
        quickQueryTimestamp.set(value)
    }

    /**
     * The directory where the reports will be written. Defaults to 'build/reports'.
     */
    @InputDirectory
    @Optional
    DirectoryProperty getOutputDirectory() {
        return outputDirectory
    }

    void setOutputDirectory(String value) {
        outputDirectory.set(project.file(value))
    }

    void setOutputDirectory(File value) {
        outputDirectory.set(value)
    }

    /**
     * The path to the suppression file.
     */
    @Input
    @Optional
    Property<String> getSuppressionFile() {
        return suppressionFile
    }

    void setSuppressionFile(String value) {
        suppressionFile.set(value)
    }

    /**
     * The list of paths to suppression files.
     */
    @Input
    @Optional
    ListProperty<String> getSuppressionFiles() {
        return suppressionFiles
    }

    void setSuppressionFiles(java.lang.Object[] files) {
        if (files != null) {
            suppressionFiles.set(Arrays.stream(files).map({ o -> o.toString() }).collect(Collectors.toList()))
        }
    }

    void setSuppressionFiles(Collection<String> files) {
        if (files != null) {
            suppressionFiles.set(files.toList())
        }
    }

    /**
     * The username for downloading the suppression file(s) from HTTP Basic protected locations
     */
    @Input
    @Optional
    Property<String> getSuppressionFileUser() {
        return suppressionFileUser
    }

    void setSuppressionFileUser(String value) {
        suppressionFileUser.set(value)
    }

    /**
     * The password for downloading the suppression file(s) from HTTP Basic protected locations
     */
    @Input
    @Optional
    Property<String> getSuppressionFilePassword() {
        return suppressionFilePassword
    }

    void setSuppressionFilePassword(String value) {
        suppressionFilePassword.set(value)
    }

    /**
     * The token for downloading the suppression file(s) from HTTP Bearer protected locations
     */
    @Input
    @Optional
    Property<String> getSuppressionFileBearerToken() {
        return suppressionFileBearerToken
    }

    void setSuppressionFileBearerToken(String value) {
        suppressionFileBearerToken.set(value)
    }

    /**
     * The path to the hints file.
     */
    @Input
    @Optional
    Property<String> getHintsFile() {
        return hintsFile
    }

    void setHintsFile(String value) {
        hintsFile.set(value)
    }

    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled.
     */
    @Input
    @Optional
    Property<Boolean> getAutoUpdate() {
        return autoUpdate
    }

    void setAutoUpdate(Boolean value) {
        autoUpdate.set(value)
    }

    /**
     * When set to true configurations that are considered a test configuration will not be included in the analysis.
     * A configuration is considered a test configuration if and only if any of the following conditions holds:
     * <ul>
     *     <li>the name of the configuration or any of its parent configurations equals 'testCompile'</li>
     *     <li>the name of the configuration or any of its parent configurations equals 'testImplementation'</li>
     *     <li>the name of the configuration or any of its parent configurations equals 'androidTestCompile'</li>
     *     <li>the configuration name starts with 'test'</li>
     *     <li>the configuration name starts with 'androidTest'</li>
     * </ul>
     * The default value is true.
     */
    @Input
    @Optional
    Property<Boolean> getSkipTestGroups() {
        return skipTestGroups
    }

    void setSkipTestGroups(Boolean value) {
        skipTestGroups.set(value)
    }

    /**
     * The report format to be generated (HTML, XML, CSV, JUNIT, SARIF, ALL). This configuration option has
     * no affect if using this within the Site plugin unless the externalReport is set to true.
     * The default is HTML.
     */
    @Input
    @Optional
    Property<String> getFormat() {
        return format
    }

    void setFormat(String value) {
        format.set(value)
    }

    /**
     * The list of formats to generate to report (HTML, XML, CSV, JUNIT, SARIF, ALL).
     */
    @Input
    @Optional
    ListProperty<String> getFormats() {
        return formats
    }

    void setFormats(List<String> value) {
        formats.set(value)
    }

    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is
     * 11 which means since the CVSS scores are 0-10, by default the build will never fail.
     */
    @Input
    @Optional
    Property<Float> getFailBuildOnCVSS() {
        return failBuildOnCVSS
    }

    void setFailBuildOnCVSS(Float value) {
        failBuildOnCVSS.set(value)
    }

    /**
     * Specifies the CVSS score that should be considered a failure when generating a JUNIT formatted report. The default
     * is 0.0 which means all identified vulnerabilities would be considered a failure.
     */
    @Input
    @Optional
    Property<Float> getJunitFailOnCVSS() {
        return junitFailOnCVSS
    }

    void setJunitFailOnCVSS(Float value) {
        junitFailOnCVSS.set(value)
    }

    /**
     * Specifies that if any unused suppression rule is found, the build will fail.
     */
    @Input
    @Optional
    Property<Boolean> getFailBuildOnUnusedSuppressionRule() {
        return failBuildOnUnusedSuppressionRule
    }

    void setFailBuildOnUnusedSuppressionRule(Boolean value) {
        failBuildOnUnusedSuppressionRule.set(value)
    }

    /**
     * Displays a summary of the findings. Defaults to true.
     */
    @Input
    @Optional
    Property<Boolean> getShowSummary() {
        return showSummary
    }

    void setShowSummary(Boolean value) {
        showSummary.set(value)
    }

    /**
     * Names of the configurations to scan.
     *
     * This is mutually exclusive with the skipConfigurations property.
     */
    @Input
    @Optional
    ListProperty<String> getScanConfigurations() {
        return scanConfigurations
    }

    void setScanConfigurations(List<String> value) {
        scanConfigurations.set(value)
    }

    /**
     * Names of the configurations to skip when scanning.
     *
     * This is mutually exclusive with the scanConfigurations property.
     */
    @Input
    @Optional
    ListProperty<String> getSkipConfigurations() {
        return skipConfigurations
    }

    void setSkipConfigurations(List<String> value) {
        skipConfigurations.set(value)
    }

    /**
     * Paths of the projects to scan.
     *
     * This is mutually exclusive with the skipProjects property.
     */
    @Input
    @Optional
    ListProperty<String> getScanProjects() {
        return scanProjects
    }

    void setScanProjects(List<String> value) {
        scanProjects.set(value)
    }

    /**
     * Paths of the projects to skip when scanning.
     *
     * This is mutually exclusive with the scanProjects property.
     */
    @Input
    @Optional
    ListProperty<String> getSkipProjects() {
        return skipProjects
    }

    void setSkipProjects(List<String> value) {
        skipProjects.set(value)
    }

    /**
     * Group prefixes of the modules to skip when scanning.
     *
     * The 'project' prefix can be used to skip all internal dependencies from multi-project build.
     */
    @Input
    @Optional
    ListProperty<String> getSkipGroups() {
        return skipGroups
    }

    void setSkipGroups(List<String> value) {
        skipGroups.set(value)
    }

    /**
     * The artifact types that will be analyzed in the gradle build.
     */
    @Input
    @Optional
    ListProperty<String> getAnalyzedTypes() {
        return analyzedTypes
    }

    void setAnalyzedTypes(List<String> value) {
        analyzedTypes.set(value)
    }

    /**
     * whether to skip the execution of dependency-check.
     */
    @Input
    @Optional
    Property<Boolean> getSkip() {
        return skip
    }

    void setSkip(Boolean value) {
        skip.set(value)
    }

    /**
     * A set of files or folders to scan.
     */
    @InputFiles
    @Optional
    ConfigurableFileCollection getScanSet() {
        return scanSet
    }

    void setScanSet(List<File> files) {
        scanSet.setFrom(files)
    }

    void setScanSet(File... files) {
        scanSet.setFrom(files)
    }


    /**
     * Allows programmatic configuration of the proxy extension
     * @param configClosure the closure to configure the proxy extension
     * @return the proxy extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def proxy(Closure configClosure) {
        return project.configure(proxy, configClosure)
    }

    /**
     * Allows programmatic configuration of the proxy extension
     * @param config the action to configure the proxy extension
     * @return the proxy extension
     */
    def proxy(Action<ProxyExtension> config) {
        config.execute(proxy)
        return proxy
    }

    /**
     * Allows programmatic configuration of the slack extension
     * @param configClosure the closure to configure the slack extension
     * @return the slack extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def slack(Closure configClosure) {
        return project.configure(slack, configClosure)
    }

    /**
     * Allows programmatic configuration of the slack extension
     * @param config the action to configure the slack extension
     * @return the slack extension
     */
    def slack(Action<SlackExtension> config) {
        config.execute(slack)
        return slack
    }

    /**
     * Allows programmatic configuration of the nvd extension
     * @param configClosure the closure to configure the nvd extension
     * @return the nvd extension
     * n @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def nvd(Closure configClosure) {
        return project.configure(nvd, configClosure)
    }

    /**
     * Allows programmatic configuration of the nvd extension
     * @param config the action to configure the nvd extension
     * @return the nvd extension
     */
    def nvd(Action<NvdExtension> config) {
        config.execute(nvd)
        return nvd
    }

    /**
     * Allows programmatic configuration of the hostedSuppressions extension.
     * @param configClosure the closure to configure the hostedSuppressions extension
     * @return the hostedSuppressions extension
     * n @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def hostedSuppressions(Closure configClosure) {
        return project.configure(hostedSuppressions, configClosure)
    }

    /**
     * Allows programmatic configuration of the hostedSuppressions extension.
     * @param config the action to configure the hostedSuppressions extension
     * @return the hostedSuppressions extension
     */
    def hostedSuppressions(Action<HostedSuppressionsExtension> config) {
        config.execute(hostedSuppressions)
        return hostedSuppressions
    }

    /**
     * Allows programmatic configuration of the analyzer extension
     * @param configClosure the closure to configure the analyzers extension
     * @return the analyzers extension
     * @deprecated Use the {@code Action} variant instead @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def analyzers(Closure configClosure) {
        return project.configure(analyzers, configClosure)
    }

    /**
     * Allows programmatic configuration of the analyzer extension
     * @param config the action to configure the analyzers extension
     * @return the analyzers extension
     */
    def analyzers(Action<AnalyzerExtension> config) {
        config.execute(analyzers)
        return analyzers
    }

    /**
     * Allows programmatic configuration of the data extension
     * @param configClosure the closure to configure the data extension
     * @return the data extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def data(Closure configClosure) {
        return project.configure(data, configClosure)
    }

    /**
     * Allows programmatic configuration of the data extension
     * @param config the action to configure the data extension
     * @return the data extension
     */
    def data(Action<DataExtension> config) {
        config.execute(data)
        return data
    }

    /**
     * Allows programmatic configuration of the cache extension
     * @param configClosure the closure to configure the cache extension
     * @return the cache extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def cache(Closure configClosure) {
        return project.configure(cache, configClosure)
    }

    /**
     * Allows programmatic configuration of the cache extension
     * @param config the action to configure the cache extension
     * @return the cache extension
     */
    def cache(Action<CacheExtension> config) {
        config.execute(cache)
        return cache
    }

    /**
     * Allows programmatic configuration of additional CPEs to be analyzed
     * @param action the action used to add entries to additional CPEs container.
     */
    def additionalCpes(Action<NamedDomainObjectContainer<AdditionalCpe>> action) {
        action.execute(additionalCpes)
    }
}

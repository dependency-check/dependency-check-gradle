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

import org.gradle.api.Action
import org.gradle.api.Project
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The analyzer configuration extension. Any value not configured will use the dependency-check-core defaults.
 */
@groovy.transform.CompileStatic
class AnalyzerExtension {

    private final Property<Boolean> experimentalEnabled
    private final Property<Boolean> archiveEnabled
    private final Property<String> zipExtensions
    private final Property<Boolean> jarEnabled
    private final Property<Boolean> centralEnabled
    private final Property<Boolean> nexusEnabled
    private final Property<String> nexusUrl
    private final Property<Boolean> nexusUsesProxy
    private final Property<Boolean> nuspecEnabled
    private final Property<Boolean> assemblyEnabled
    private final Property<Boolean> msbuildEnabled
    private final Property<String> pathToDotnet
    private final Property<Boolean> golangDepEnabled
    private final Property<Boolean> golangModEnabled
    private final Property<String> pathToGo
    private final Property<Boolean> cocoapodsEnabled
    private final Property<Boolean> swiftEnabled
    private final Property<Boolean> dartEnabled
    private final Property<Boolean> swiftPackageResolvedEnabled
    private final Property<Boolean> bundleAuditEnabled
    private final Property<String> pathToBundleAudit
    private final Property<Boolean> pyDistributionEnabled
    private final Property<Boolean> pyPackageEnabled
    private final Property<Boolean> rubygemsEnabled
    private final Property<Boolean> opensslEnabled
    private final Property<Boolean> cmakeEnabled
    private final Property<Boolean> autoconfEnabled
    private final Property<Boolean> composerEnabled
    private final Property<Boolean> composerSkipDev
    private final Property<Boolean> cpanEnabled
    private final Property<Boolean> nodeEnabled
    private final Property<Boolean> nodeAuditEnabled
    private final Property<Boolean> nugetconfEnabled
    private final Property<Boolean> ossIndexEnabled

    Project project;

    @Inject
    AnalyzerExtension(Project project, ObjectFactory objects) {
        this.project = project
        this.experimentalEnabled = objects.property(Boolean)
        this.archiveEnabled = objects.property(Boolean)
        this.zipExtensions = objects.property(String)
        this.jarEnabled = objects.property(Boolean)
        this.centralEnabled = objects.property(Boolean)
        this.nexusEnabled = objects.property(Boolean)
        this.nexusUrl = objects.property(String)
        this.nexusUsesProxy = objects.property(Boolean)
        this.nuspecEnabled = objects.property(Boolean)
        this.assemblyEnabled = objects.property(Boolean)
        this.msbuildEnabled = objects.property(Boolean)
        this.pathToDotnet = objects.property(String)
        this.golangDepEnabled = objects.property(Boolean)
        this.golangModEnabled = objects.property(Boolean)
        this.pathToGo = objects.property(String)
        this.cocoapodsEnabled = objects.property(Boolean)
        this.swiftEnabled = objects.property(Boolean)
        this.dartEnabled = objects.property(Boolean)
        this.swiftPackageResolvedEnabled = objects.property(Boolean)
        this.bundleAuditEnabled = objects.property(Boolean)
        this.pathToBundleAudit = objects.property(String)
        this.pyDistributionEnabled = objects.property(Boolean)
        this.pyPackageEnabled = objects.property(Boolean)
        this.rubygemsEnabled = objects.property(Boolean)
        this.opensslEnabled = objects.property(Boolean)
        this.cmakeEnabled = objects.property(Boolean)
        this.autoconfEnabled = objects.property(Boolean)
        this.composerEnabled = objects.property(Boolean)
        this.composerSkipDev = objects.property(Boolean)
        this.cpanEnabled = objects.property(Boolean)
        this.nodeEnabled = objects.property(Boolean)
        this.nodeAuditEnabled = objects.property(Boolean)
        this.nugetconfEnabled = objects.property(Boolean)
        this.ossIndexEnabled = objects.property(Boolean)
        kev = objects.newInstance(KEVExtension, objects)
        retirejs = objects.newInstance(RetireJSExtension, objects)
        nodeAudit = objects.newInstance(NodeAuditExtension, objects)
        nodePackage = objects.newInstance(NodePackageExtension, objects)
        artifactory = objects.newInstance(ArtifactoryExtension, objects)
        ossIndex = objects.newInstance(OssIndexExtension, objects)
    }

    /**
     * Sets whether the experimental analyzers will be used.
     */
    @Input
    @Optional
    Property<Boolean> getExperimentalEnabled() {
        return experimentalEnabled
    }

    void setExperimentalEnabled(Boolean value) {
        experimentalEnabled.set(value)
    }

    /**
     * Sets whether the Archive Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getArchiveEnabled() {
        return archiveEnabled
    }

    void setArchiveEnabled(Boolean value) {
        archiveEnabled.set(value)
    }

    /**
     * A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed.
     */
    @Input
    @Optional
    Property<String> getZipExtensions() {
        return zipExtensions
    }

    void setZipExtensions(String value) {
        zipExtensions.set(value)
    }

    /**
     * Sets whether Jar Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getJarEnabled() {
        return jarEnabled
    }

    void setJarEnabled(Boolean value) {
        jarEnabled.set(value)
    }

    /**
     * Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below).
     */
    @Input
    @Optional
    Property<Boolean> getCentralEnabled() {
        return centralEnabled
    }

    void setCentralEnabled(Boolean value) {
        centralEnabled.set(value)
    }

    /**
     * Sets whether Nexus Analyzer will be used. This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation.
     */
    @Input
    @Optional
    Property<Boolean> getNexusEnabled() {
        return nexusEnabled
    }

    void setNexusEnabled(Boolean value) {
        nexusEnabled.set(value)
    }

    /**
     * Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled.
     */
    @Input
    @Optional
    Property<String> getNexusUrl() {
        return nexusUrl
    }

    void setNexusUrl(String value) {
        nexusUrl.set(value)
    }

    /**
     * whether the defined proxy should be used when connecting to Nexus.
     */
    @Input
    @Optional
    Property<Boolean> getNexusUsesProxy() {
        return nexusUsesProxy
    }

    void setNexusUsesProxy(Boolean value) {
        nexusUsesProxy.set(value)
    }

    /**
     * Sets whether the .NET Nuget Nuspec Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getNuspecEnabled() {
        return nuspecEnabled
    }

    void setNuspecEnabled(Boolean value) {
        nuspecEnabled.set(value)
    }

    /**
     * Sets whether the .NET Assembly Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getAssemblyEnabled() {
        return assemblyEnabled
    }

    void setAssemblyEnabled(Boolean value) {
        assemblyEnabled.set(value)
    }

    /**
     * Sets whether the MS Build Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getMsbuildEnabled() {
        return msbuildEnabled
    }

    void setMsbuildEnabled(Boolean value) {
        msbuildEnabled.set(value)
    }

    /**
     * The path to dotnet core - used to analyze dot net assemblies.
     */
    @Input
    @Optional
    Property<String> getPathToDotnet() {
        return pathToDotnet
    }

    void setPathToDotnet(String value) {
        pathToDotnet.set(value)
    }

    /**
     * Sets whether the Golang Dependency analyzer is enabled. Default is true.
     */
    @Input
    @Optional
    Property<Boolean> getGolangDepEnabled() {
        return golangDepEnabled
    }

    void setGolangDepEnabled(Boolean value) {
        golangDepEnabled.set(value)
    }

    /**
     * Sets whether Golang Module Analyzer is enabled; this requires `go` to be
     * installed. Default is true.
     */
    @Input
    @Optional
    Property<Boolean> getGolangModEnabled() {
        return golangModEnabled
    }

    void setGolangModEnabled(Boolean value) {
        golangModEnabled.set(value)
    }

    /**
     * The path to `go` - used to analyze go modules via `go mod`.
     */
    @Input
    @Optional
    Property<String> getPathToGo() {
        return pathToGo
    }

    void setPathToGo(String value) {
        pathToGo.set(value)
    }

    /**
     * Sets whether the cocoapods analyzer is enabled.
     */
    @Input
    @Optional
    Property<Boolean> getCocoapodsEnabled() {
        return cocoapodsEnabled
    }

    void setCocoapodsEnabled(Boolean value) {
        cocoapodsEnabled.set(value)
    }

    /**
     * Sets whether the swift package manager analyzer is enabled.
     */
    @Input
    @Optional
    Property<Boolean> getSwiftEnabled() {
        return swiftEnabled
    }

    void setSwiftEnabled(Boolean value) {
        swiftEnabled.set(value)
    }

    /**
     * Sets whether the swift package manager analyzer is enabled.
     */
    @Input
    @Optional
    Property<Boolean> getDartEnabled() {
        return dartEnabled
    }

    void setDartEnabled(Boolean value) {
        dartEnabled.set(value)
    }

    /**
     * Sets whether the swift package resolved analyzer is enabled.
     */
    @Input
    @Optional
    Property<Boolean> getSwiftPackageResolvedEnabled() {
        return swiftPackageResolvedEnabled
    }

    void setSwiftPackageResolvedEnabled(Boolean value) {
        swiftPackageResolvedEnabled.set(value)
    }

    /**
     * Sets whether the Ruby Bundle Audit analyzer is enabled; requires running bundle audit.
     */
    @Input
    @Optional
    Property<Boolean> getBundleAuditEnabled() {
        return bundleAuditEnabled
    }

    void setBundleAuditEnabled(Boolean value) {
        bundleAuditEnabled.set(value)
    }

    /**
     * The path to Ruby's bundle audit.
     */
    @Input
    @Optional
    Property<String> getPathToBundleAudit() {
        return pathToBundleAudit
    }

    void setPathToBundleAudit(String value) {
        pathToBundleAudit.set(value)
    }

    /**
     * Sets whether the Python Distribution Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getPyDistributionEnabled() {
        return pyDistributionEnabled
    }

    void setPyDistributionEnabled(Boolean value) {
        pyDistributionEnabled.set(value)
    }

    /**
     * Sets whether the Python Package Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getPyPackageEnabled() {
        return pyPackageEnabled
    }

    void setPyPackageEnabled(Boolean value) {
        pyPackageEnabled.set(value)
    }

    /**
     * Sets whether the Ruby Gemspec Analyzer will be used.
     */
    @Input
    @Optional
    Property<Boolean> getRubygemsEnabled() {
        return rubygemsEnabled
    }

    void setRubygemsEnabled(Boolean value) {
        rubygemsEnabled.set(value)
    }

    /**
     * Sets whether the openssl Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getOpensslEnabled() {
        return opensslEnabled
    }

    void setOpensslEnabled(Boolean value) {
        opensslEnabled.set(value)
    }

    /**
     * Sets whether the CMake Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getCmakeEnabled() {
        return cmakeEnabled
    }

    void setCmakeEnabled(Boolean value) {
        cmakeEnabled.set(value)
    }

    /**
     * Sets whether the autoconf Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getAutoconfEnabled() {
        return autoconfEnabled
    }

    void setAutoconfEnabled(Boolean value) {
        autoconfEnabled.set(value)
    }

    /**
     * Sets whether the PHP Composer Lock File Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getComposerEnabled() {
        return composerEnabled
    }

    void setComposerEnabled(Boolean value) {
        composerEnabled.set(value)
    }

    /**
     * Sets whether the PHP Composer Lock File Analyzer should skip packages-dev dependencies.
     */
    @Input
    @Optional
    Property<Boolean> getComposerSkipDev() {
        return composerSkipDev
    }

    void setComposerSkipDev(Boolean value) {
        composerSkipDev.set(value)
    }

    /**
     * Sets whether the Perl CPAN File Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getCpanEnabled() {
        return cpanEnabled
    }

    void setCpanEnabled(Boolean value) {
        cpanEnabled.set(value)
    }

    /**
     * Sets whether the Node.js Analyzer should be used.
     * @deprecated Use nodePackage { enabled = true }
     */
    @Input
    @Optional
    @Deprecated
    Property<Boolean> getNodeEnabled() {
        return nodeEnabled
    }

    void setNodeEnabled(Boolean value) {
        nodeEnabled.set(value)
    }

    /**
     * Sets whether the NSP Analyzer should be used.
     * @deprecated As of the 5.2.5 - please use nodeAudit { enabled = true }
     */
    @Input
    @Optional
    @Deprecated
    Property<Boolean> getNodeAuditEnabled() {
        return nodeAuditEnabled
    }

    void setNodeAuditEnabled(Boolean value) {
        nodeAuditEnabled.set(value)
    }

    /**
     * Sets whether the Nuget packages.config Configuration Analyzer should be used.
     */
    @Input
    @Optional
    Property<Boolean> getNugetconfEnabled() {
        return nugetconfEnabled
    }

    void setNugetconfEnabled(Boolean value) {
        nugetconfEnabled.set(value)
    }

    /**
     * Sets whether the OSS Index Analyzer should be used.
     * @deprecated As of the 5.0.1 - please use ossIndex { enabled = true }
     */
    @Input
    @Optional
    @Deprecated
    Property<Boolean> getOssIndexEnabled() {
        return ossIndexEnabled
    }

    void setOssIndexEnabled(Boolean value) {
        ossIndexEnabled.set(value)
    }

    /**
     * The configuration extension for known exploited vulnerabilities settings.
     */
    KEVExtension kev

    /**
     * The configuration extension for retirejs settings.
     */
    RetireJSExtension retirejs

    /**
     * The configuration extension for the node audit settings.
     */
    NodeAuditExtension nodeAudit

    /**
     * The configuration extension for the node package settings.
     */
    NodePackageExtension nodePackage

    /**
     * The configuration extension for artifactory settings.
     */
    ArtifactoryExtension artifactory

    /**
     * The configuration extension for artifactory settings.
     */
    OssIndexExtension ossIndex

    /**
     * Allows programmatic configuration of the KEV extension
     * @param configClosure the closure to configure the KEV extension
     * @return the KEV extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated
    def kev(Closure configClosure) {
        return project.configure(kev, configClosure)
    }

    /**
     * Allows programmatic configuration of the KEV extension
     * @param config the action to configure the KEV extension
     * @return the KEV extension
     */
    def kev(Action<KEVExtension> config) {
        config.execute(kev)
        return kev
    }

    /**
     * Allows programmatic configuration of the retirejs extension
     * @param configClosure the closure to configure the retirejs extension
     * @return the retirejs extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated()
    def retirejs(Closure configClosure) {
        return project.configure(retirejs, configClosure)
    }

    /**
     * Allows programmatic configuration of the retirejs extension
     * @param config the action to configure the retirejs extension
     * @return the retirejs extension
     */
    def retirejs(Action<RetireJSExtension> config) {
        config.execute(retirejs)
        return retirejs
    }

    /**
     * Allows programmatic configuration of the artifactory extension
     * @param configClosure the closure to configure the artifactory extension
     * @return the artifactory extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated()
    def artifactory(Closure configClosure) {
        return project.configure(artifactory, configClosure)
    }

    /**
     * Allows programmatic configuration of the artifactory extension
     * @param config the action to configure the artifactory extension
     * @return the artifactory extension
     */
    def artifactory(Action<ArtifactoryExtension> config) {
        config.execute(artifactory)
        return artifactory
    }

    /**
     * Allows programmatic configuration of the ossIndex extension
     * @param configClosure the closure to configure the ossIndex extension
     * @return the ossIndex extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated()
    def ossIndex(Closure configClosure) {
        return project.configure(ossIndex, configClosure)
    }

    /**
     * Allows programmatic configuration of the ossIndex extension
     * @param config the action to configure the ossIndex extension
     * @return the ossIndex extension
     */
    def ossIndex(Action<OssIndexExtension> config) {
        config.execute(ossIndex)
        return ossIndex
    }

    /**
     * Allows programmatic configuration of the nodeAudit extension
     * @param configClosure the closure to configure the ossIndex extension
     * @return the ossIndex extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated()
    def nodeAudit(Closure configClosure) {
        return project.configure(nodeAudit, configClosure)
    }

    /**
     * Allows programmatic configuration of the nodeAudit extension
     * @param config the action to configure the ossIndex extension
     * @return the ossIndex extension
     */
    def nodeAudit(Action<NodeAuditExtension> config) {
        config.execute(nodeAudit)
        return nodeAudit
    }

    /**
     * Allows programmatic configuration of the node package extension
     * @param configClosure the closure to configure the node extension
     * @return the node extension
     * @deprecated Use the {@code Action} variant instead
     */
    @Deprecated()
    def nodePackage(Closure configClosure) {
        return project.configure(nodePackage, configClosure)
    }

    /**
     * Allows programmatic configuration of the node package extension
     * @param config the action to configure the node extension
     * @return the node extension
     */
    def nodePackage(Action<NodePackageExtension> config) {
        config.execute(nodePackage)
        return nodePackage
    }
}

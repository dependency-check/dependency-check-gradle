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

package org.owasp.dependencycheck.gradle.tasks

import com.github.packageurl.PackageURL
import com.github.packageurl.PackageURLBuilder
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ModuleVersionIdentifier
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ComponentArtifactsResult
import org.gradle.api.artifacts.result.DependencyResult
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
import org.gradle.api.attributes.Attribute
import org.gradle.api.InvalidUserDataException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.maven.MavenModule
import org.gradle.maven.MavenPomArtifact
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent
import org.owasp.dependencycheck.gradle.extension.AnalyzerExtension
import org.owasp.dependencycheck.gradle.extension.CacheExtension
import org.owasp.dependencycheck.gradle.extension.HostedSuppressionsExtension
import org.owasp.dependencycheck.gradle.extension.SlackExtension
import org.owasp.dependencycheck.data.nexus.MavenArtifact
import org.owasp.dependencycheck.data.nvdcve.DatabaseException
import org.owasp.dependencycheck.dependency.Confidence
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.dependency.IncludedByReference
import org.owasp.dependencycheck.dependency.Vulnerability
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier
import org.owasp.dependencycheck.exception.ExceptionCollection
import org.owasp.dependencycheck.exception.ReportException
import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.owasp.dependencycheck.utils.Checksum
import org.owasp.dependencycheck.utils.SeverityUtil
import org.owasp.dependencycheck.xml.pom.PomUtils
import us.springett.parsers.cpe.CpeParser

import javax.inject.Inject
import java.util.regex.Pattern

import static org.owasp.dependencycheck.reporting.ReportGenerator.Format
import static org.owasp.dependencycheck.utils.Settings.KEYS.*

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
@CompileStatic
abstract class AbstractAnalyze extends ConfiguredTask {

    private static final Pattern TEST_CONFIG_PATTERN = ~/((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/

    @Internal
    String currentProjectName = project.getName()
    @Internal
    Attribute artifactType = Attribute.of('artifactType', String)

    private final Map<ModuleComponentIdentifier, File> pomCache = new HashMap<>()

    /**
     * The output directory for the dependency-check reports.
     */
    @OutputDirectory
    final DirectoryProperty outputDir

    @Internal
    final Property<Boolean> skip
    @Internal
    final Property<Boolean> scanDependencies
    @Internal
    final Property<Boolean> scanBuildEnv
    @Internal
    final Property<String> suppressionFile
    @Internal
    final ListProperty<String> suppressionFiles
    @Internal
    final Property<String> suppressionFileUser
    @Internal
    final Property<String> suppressionFilePassword
    @Internal
    final Property<String> suppressionFileBearerToken
    @Internal
    final Property<String> hintsFile
    @Internal
    final Property<String> format
    @Internal
    final ListProperty<String> formats
    @Internal
    final Property<Float> failBuildOnCVSS
    @Internal
    final Property<Float> junitFailOnCVSS

    void setFailBuildOnCVSS(Number value) {
        failBuildOnCVSS.set(value?.floatValue())
    }

    void setJunitFailOnCVSS(Number value) {
        junitFailOnCVSS.set(value?.floatValue())
    }
    @Internal
    final Property<Boolean> failBuildOnUnusedSuppressionRule
    @Internal
    final Property<Boolean> showSummary
    @Internal
    final Property<Boolean> skipTestGroups
    @Internal
    final ListProperty<String> scanConfigurations
    @Internal
    final ListProperty<String> skipConfigurations
    @Internal
    final ListProperty<String> scanProjects
    @Internal
    final ListProperty<String> skipProjects
    @Internal
    final ListProperty<String> skipGroups
    @Internal
    final ListProperty<String> analyzedTypes

    @Internal
    final SlackExtension slack
    @Internal
    final HostedSuppressionsExtension hostedSuppressions
    @Internal
    final CacheExtension cache
    @Internal
    final AnalyzerExtension analyzers

    @Inject
    AbstractAnalyze(ObjectFactory objects) {
        super(objects)
        outputDir = objects.directoryProperty().convention(defaults.outputDirectory)
        super.notCompatibleWithConfigurationCache("${this.class.simpleName} isn't compatible with the configuration cache")

        skip = objects.property(Boolean).convention(defaults.skip)
        scanDependencies = objects.property(Boolean).convention(defaults.scanDependencies)
        scanBuildEnv = objects.property(Boolean).convention(defaults.scanBuildEnv)
        suppressionFile = objects.property(String).convention(defaults.suppressionFile)
        suppressionFiles = objects.listProperty(String).convention(defaults.suppressionFiles)
        suppressionFileUser = objects.property(String).convention(defaults.suppressionFileUser)
        suppressionFilePassword = objects.property(String).convention(defaults.suppressionFilePassword)
        suppressionFileBearerToken = objects.property(String).convention(defaults.suppressionFileBearerToken)
        hintsFile = objects.property(String).convention(defaults.hintsFile)
        format = objects.property(String).convention(defaults.format)
        formats = objects.listProperty(String).convention(defaults.formats)
        failBuildOnCVSS = objects.property(Float).convention(defaults.failBuildOnCVSS)
        junitFailOnCVSS = objects.property(Float).convention(defaults.junitFailOnCVSS)
        failBuildOnUnusedSuppressionRule = objects.property(Boolean).convention(defaults.failBuildOnUnusedSuppressionRule)
        showSummary = objects.property(Boolean).convention(defaults.showSummary)
        skipTestGroups = objects.property(Boolean).convention(defaults.skipTestGroups)
        scanConfigurations = objects.listProperty(String).convention(defaults.scanConfigurations)
        skipConfigurations = objects.listProperty(String).convention(defaults.skipConfigurations)
        scanProjects = objects.listProperty(String).convention(defaults.scanProjects)
        skipProjects = objects.listProperty(String).convention(defaults.skipProjects)
        skipGroups = objects.listProperty(String).convention(defaults.skipGroups)
        analyzedTypes = objects.listProperty(String).convention(defaults.analyzedTypes)

        slack = objects.newInstance(SlackExtension, objects)
        slack.enabled.convention(defaults.slack.enabled)
        slack.webhookUrl.convention(defaults.slack.webhookUrl)

        hostedSuppressions = objects.newInstance(HostedSuppressionsExtension, objects)
        hostedSuppressions.enabled.convention(defaults.hostedSuppressions.enabled)
        hostedSuppressions.forceupdate.convention(defaults.hostedSuppressions.forceupdate)
        hostedSuppressions.url.convention(defaults.hostedSuppressions.url)
        hostedSuppressions.user.convention(defaults.hostedSuppressions.user)
        hostedSuppressions.password.convention(defaults.hostedSuppressions.password)
        hostedSuppressions.bearerToken.convention(defaults.hostedSuppressions.bearerToken)
        hostedSuppressions.validForHours.convention(defaults.hostedSuppressions.validForHours)

        cache = objects.newInstance(CacheExtension, objects)
        cache.nodeAudit.convention(defaults.cache.nodeAudit)
        cache.central.convention(defaults.cache.central)
        cache.ossIndex.convention(defaults.cache.ossIndex)

        analyzers = objects.newInstance(AnalyzerExtension, project, objects)
        analyzers.jarEnabled.convention(defaults.analyzers.jarEnabled)
        analyzers.nuspecEnabled.convention(defaults.analyzers.nuspecEnabled)
        analyzers.centralEnabled.convention(defaults.analyzers.centralEnabled)
        analyzers.experimentalEnabled.convention(defaults.analyzers.experimentalEnabled)
        analyzers.archiveEnabled.convention(defaults.analyzers.archiveEnabled)
        analyzers.zipExtensions.convention(defaults.analyzers.zipExtensions)
        analyzers.assemblyEnabled.convention(defaults.analyzers.assemblyEnabled)
        analyzers.msbuildEnabled.convention(defaults.analyzers.msbuildEnabled)
        analyzers.pathToDotnet.convention(defaults.analyzers.pathToDotnet)
        analyzers.golangDepEnabled.convention(defaults.analyzers.golangDepEnabled)
        analyzers.golangModEnabled.convention(defaults.analyzers.golangModEnabled)
        analyzers.pathToGo.convention(defaults.analyzers.pathToGo)
        analyzers.cocoapodsEnabled.convention(defaults.analyzers.cocoapodsEnabled)
        analyzers.swiftEnabled.convention(defaults.analyzers.swiftEnabled)
        analyzers.dartEnabled.convention(defaults.analyzers.dartEnabled)
        analyzers.swiftPackageResolvedEnabled.convention(defaults.analyzers.swiftPackageResolvedEnabled)
        analyzers.bundleAuditEnabled.convention(defaults.analyzers.bundleAuditEnabled)
        analyzers.pathToBundleAudit.convention(defaults.analyzers.pathToBundleAudit)
        analyzers.pyDistributionEnabled.convention(defaults.analyzers.pyDistributionEnabled)
        analyzers.pyPackageEnabled.convention(defaults.analyzers.pyPackageEnabled)
        analyzers.rubygemsEnabled.convention(defaults.analyzers.rubygemsEnabled)
        analyzers.opensslEnabled.convention(defaults.analyzers.opensslEnabled)
        analyzers.cmakeEnabled.convention(defaults.analyzers.cmakeEnabled)
        analyzers.autoconfEnabled.convention(defaults.analyzers.autoconfEnabled)
        analyzers.composerEnabled.convention(defaults.analyzers.composerEnabled)
        analyzers.composerSkipDev.convention(defaults.analyzers.composerSkipDev)
        analyzers.cpanEnabled.convention(defaults.analyzers.cpanEnabled)
        analyzers.nodeEnabled.convention(defaults.analyzers.nodeEnabled)
        analyzers.nodeAuditEnabled.convention(defaults.analyzers.nodeAuditEnabled)
        analyzers.nugetconfEnabled.convention(defaults.analyzers.nugetconfEnabled)
        analyzers.ossIndexEnabled.convention(defaults.analyzers.ossIndexEnabled)

        analyzers.ossIndex.enabled.convention(defaults.analyzers.ossIndex.enabled)
        analyzers.ossIndex.warnOnlyOnRemoteErrors.convention(defaults.analyzers.ossIndex.warnOnlyOnRemoteErrors)
        analyzers.ossIndex.username.convention(defaults.analyzers.ossIndex.username)
        analyzers.ossIndex.password.convention(defaults.analyzers.ossIndex.password)
        analyzers.ossIndex.url.convention(defaults.analyzers.ossIndex.url)
        analyzers.ossIndex.validForHours.convention(defaults.analyzers.ossIndex.validForHours)

        analyzers.nexus.enabled.convention(defaults.analyzers.nexus.enabled)
        analyzers.nexus.url.convention(defaults.analyzers.nexus.url)
        analyzers.nexus.usesProxy.convention(defaults.analyzers.nexus.usesProxy)
        analyzers.nexus.username.convention(defaults.analyzers.nexus.username)
        analyzers.nexus.password.convention(defaults.analyzers.nexus.password)

        analyzers.kev.enabled.convention(defaults.analyzers.kev.enabled)
        analyzers.kev.url.convention(defaults.analyzers.kev.url)
        analyzers.kev.validForHours.convention(defaults.analyzers.kev.validForHours)
        analyzers.kev.user.convention(defaults.analyzers.kev.user)
        analyzers.kev.password.convention(defaults.analyzers.kev.password)
        analyzers.kev.bearerToken.convention(defaults.analyzers.kev.bearerToken)

        analyzers.nodePackage.enabled.convention(defaults.analyzers.nodePackage.enabled)
        analyzers.nodePackage.skipDevDependencies.convention(defaults.analyzers.nodePackage.skipDevDependencies)

        analyzers.nodeAudit.enabled.convention(defaults.analyzers.nodeAudit.enabled)
        analyzers.nodeAudit.useCache.convention(defaults.analyzers.nodeAudit.useCache)
        analyzers.nodeAudit.skipDevDependencies.convention(defaults.analyzers.nodeAudit.skipDevDependencies)
        analyzers.nodeAudit.url.convention(defaults.analyzers.nodeAudit.url)
        analyzers.nodeAudit.yarnEnabled.convention(defaults.analyzers.nodeAudit.yarnEnabled)
        analyzers.nodeAudit.yarnPath.convention(defaults.analyzers.nodeAudit.yarnPath)
        analyzers.nodeAudit.pnpmEnabled.convention(defaults.analyzers.nodeAudit.pnpmEnabled)
        analyzers.nodeAudit.pnpmPath.convention(defaults.analyzers.nodeAudit.pnpmPath)

        analyzers.retirejs.enabled.convention(defaults.analyzers.retirejs.enabled)
        analyzers.retirejs.forceupdate.convention(defaults.analyzers.retirejs.forceupdate)
        analyzers.retirejs.retireJsUrl.convention(defaults.analyzers.retirejs.retireJsUrl)
        analyzers.retirejs.user.convention(defaults.analyzers.retirejs.user)
        analyzers.retirejs.password.convention(defaults.analyzers.retirejs.password)
        analyzers.retirejs.bearerToken.convention(defaults.analyzers.retirejs.bearerToken)
        analyzers.retirejs.filterNonVulnerable.convention(defaults.analyzers.retirejs.filterNonVulnerable)
        analyzers.retirejs.filters.convention(defaults.analyzers.retirejs.filters)

        analyzers.artifactory.enabled.convention(defaults.analyzers.artifactory.enabled)
        analyzers.artifactory.parallelAnalysis.convention(defaults.analyzers.artifactory.parallelAnalysis)
        analyzers.artifactory.usesProxy.convention(defaults.analyzers.artifactory.usesProxy)
        analyzers.artifactory.url.convention(defaults.analyzers.artifactory.url)
        analyzers.artifactory.apiToken.convention(defaults.analyzers.artifactory.apiToken)
        analyzers.artifactory.username.convention(defaults.analyzers.artifactory.username)
        analyzers.artifactory.bearerToken.convention(defaults.analyzers.artifactory.bearerToken)
    }

    @Override
    protected void initializeSettings() {
        super.initializeSettings()

        String[] suppressionLists = determineSuppressions(suppressionFiles.getOrElse([]), suppressionFile.getOrNull())
        settings.setArrayIfNotEmpty(SUPPRESSION_FILE, suppressionLists)
        settings.setStringIfNotEmpty(SUPPRESSION_FILE_USER, suppressionFileUser.getOrNull())
        settings.setStringIfNotEmpty(SUPPRESSION_FILE_PASSWORD, suppressionFilePassword.getOrNull())
        settings.setStringIfNotEmpty(SUPPRESSION_FILE_BEARER_TOKEN, suppressionFileBearerToken.getOrNull())
        settings.setStringIfNotEmpty(HINTS_FILE, hintsFile.getOrNull())

        configureSlack(settings)

        settings.setFloat(JUNIT_FAIL_ON_CVSS, junitFailOnCVSS.get())
        settings.setBooleanIfNotNull(FAIL_ON_UNUSED_SUPPRESSION_RULE, failBuildOnUnusedSuppressionRule.getOrNull())
        settings.setBooleanIfNotNull(HOSTED_SUPPRESSIONS_ENABLED, hostedSuppressions.enabled.getOrNull())
        settings.setBooleanIfNotNull(HOSTED_SUPPRESSIONS_FORCEUPDATE, hostedSuppressions.forceupdate.getOrNull())
        settings.setStringIfNotNull(HOSTED_SUPPRESSIONS_URL, hostedSuppressions.url.getOrNull())
        settings.setStringIfNotNull(HOSTED_SUPPRESSIONS_USER, hostedSuppressions.user.getOrNull())
        settings.setStringIfNotNull(HOSTED_SUPPRESSIONS_PASSWORD, hostedSuppressions.password.getOrNull())
        settings.setStringIfNotNull(HOSTED_SUPPRESSIONS_BEARER_TOKEN, hostedSuppressions.bearerToken.getOrNull())
        if (hostedSuppressions.validForHours.getOrNull() != null) {
            if (hostedSuppressions.validForHours.getOrNull() >= 0) {
                settings.setInt(HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, hostedSuppressions.validForHours.getOrNull())
            } else {
                throw new InvalidUserDataException('Invalid setting: `validForHours` must be 0 or greater')
            }
        }

        settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, analyzers.jarEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, analyzers.nuspecEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, select(analyzers.ossIndex.enabled.getOrNull(), analyzers.ossIndexEnabled.getOrNull()))
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, analyzers.ossIndex.warnOnlyOnRemoteErrors.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_ENABLED, analyzers.ossIndex.enabled.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_USER, analyzers.ossIndex.username.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_PASSWORD, analyzers.ossIndex.password.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_OSSINDEX_URL, analyzers.ossIndex.url.getOrNull())
        settings.setIntIfNotNull(ANALYZER_OSSINDEX_CACHE_VALID_FOR_HOURS, analyzers.ossIndex.validForHours.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, analyzers.centralEnabled.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, analyzers.nexus.enabled.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, analyzers.nexus.url.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, analyzers.nexus.usesProxy.getOrNull())
        settings.setStringIfNotNull(ANALYZER_NEXUS_USER, analyzers.nexus.username.getOrNull())
        settings.setStringIfNotNull(ANALYZER_NEXUS_PASSWORD, analyzers.nexus.password.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_EXPERIMENTAL_ENABLED, analyzers.experimentalEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, analyzers.archiveEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_KNOWN_EXPLOITED_ENABLED, analyzers.kev.enabled.getOrNull())
        settings.setStringIfNotNull(KEV_URL, analyzers.kev.url.getOrNull())
        settings.setIntIfNotNull(KEV_CHECK_VALID_FOR_HOURS, analyzers.kev.validForHours.getOrNull())
        settings.setStringIfNotNull(KEV_USER, analyzers.kev.user.getOrNull())
        settings.setStringIfNotNull(KEV_PASSWORD, analyzers.kev.password.getOrNull())
        settings.setStringIfNotNull(KEV_BEARER_TOKEN, analyzers.kev.bearerToken.getOrNull())
        settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, analyzers.zipExtensions.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, analyzers.assemblyEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_MSBUILD_PROJECT_ENABLED, analyzers.msbuildEnabled.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_DOTNET_PATH, analyzers.pathToDotnet.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_DEP_ENABLED, analyzers.golangDepEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_GOLANG_MOD_ENABLED, analyzers.golangModEnabled.getOrNull())
        settings.setStringIfNotNull(ANALYZER_GOLANG_PATH, analyzers.pathToGo.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_COCOAPODS_ENABLED, analyzers.cocoapodsEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, analyzers.swiftEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_DART_ENABLED, analyzers.dartEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED, analyzers.swiftPackageResolvedEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_BUNDLE_AUDIT_ENABLED, analyzers.bundleAuditEnabled.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_BUNDLE_AUDIT_PATH, analyzers.pathToBundleAudit.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, analyzers.pyDistributionEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_PYTHON_PACKAGE_ENABLED, analyzers.pyPackageEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_RUBY_GEMSPEC_ENABLED, analyzers.rubygemsEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_OPENSSL_ENABLED, analyzers.opensslEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_CMAKE_ENABLED, analyzers.cmakeEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_AUTOCONF_ENABLED, analyzers.autoconfEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_ENABLED, analyzers.composerEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_SKIP_DEV, analyzers.composerSkipDev.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_CPANFILE_ENABLED, analyzers.cpanEnabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_NUGETCONF_ENABLED, analyzers.nugetconfEnabled.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, select(analyzers.nodePackage.enabled.getOrNull(), analyzers.nodeEnabled.getOrNull()))
        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_SKIPDEV, analyzers.nodePackage.skipDevDependencies.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, select(analyzers.nodeAudit.enabled.getOrNull(), analyzers.nodeAuditEnabled.getOrNull()))
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_USE_CACHE, analyzers.nodeAudit.useCache.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_SKIPDEV, analyzers.nodeAudit.skipDevDependencies.getOrNull())
        settings.setStringIfNotEmpty(ANALYZER_NODE_AUDIT_URL, analyzers.nodeAudit.url.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_YARN_AUDIT_ENABLED, analyzers.nodeAudit.yarnEnabled.getOrNull())
        settings.setStringIfNotNull(ANALYZER_YARN_PATH, analyzers.nodeAudit.yarnPath.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_PNPM_AUDIT_ENABLED, analyzers.nodeAudit.pnpmEnabled.getOrNull())
        settings.setStringIfNotNull(ANALYZER_PNPM_PATH, analyzers.nodeAudit.pnpmPath.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_ENABLED, analyzers.retirejs.enabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_FORCEUPDATE, analyzers.retirejs.forceupdate.getOrNull())
        settings.setStringIfNotNull(ANALYZER_RETIREJS_REPO_JS_URL, analyzers.retirejs.retireJsUrl.getOrNull())
        settings.setStringIfNotNull(ANALYZER_RETIREJS_REPO_JS_USER, analyzers.retirejs.user.getOrNull())
        settings.setStringIfNotNull(ANALYZER_RETIREJS_REPO_JS_PASSWORD, analyzers.retirejs.password.getOrNull())
        settings.setStringIfNotNull(ANALYZER_RETIREJS_REPO_JS_BEARER_TOKEN, analyzers.retirejs.bearerToken.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, analyzers.retirejs.filterNonVulnerable.getOrNull())
        settings.setArrayIfNotEmpty(ANALYZER_RETIREJS_FILTERS, analyzers.retirejs.filters.getOrElse([]))

        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_ENABLED, analyzers.artifactory.enabled.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, analyzers.artifactory.parallelAnalysis.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_USES_PROXY, analyzers.artifactory.usesProxy.getOrNull())
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_URL, analyzers.artifactory.url.getOrNull())
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_TOKEN, analyzers.artifactory.apiToken.getOrNull())
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_USERNAME, analyzers.artifactory.username.getOrNull())
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_BEARER_TOKEN, analyzers.artifactory.bearerToken.getOrNull())

        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_USE_CACHE, cache.nodeAudit.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_USE_CACHE, cache.central.getOrNull())
        settings.setBooleanIfNotNull(ANALYZER_OSSINDEX_USE_CACHE, cache.ossIndex.getOrNull())
    }

    /**
     * Calls dependency-check-core's analysis engine to scan
     * all of the projects dependencies.
     */
    @TaskAction
    analyze() {
        if (skip.get()) {
            logger.lifecycle("Skipping dependency-check-gradle")
            return
        }
        verifySettings()
        initializeSettings()
        Engine engine = null
        try {
            engine = new Engine(settings)
        } catch (DatabaseException ex) {
            String msg = "Unable to connect to the dependency-check database"
            if (failOnError.get()) {
                cleanup(engine)
                throw new GradleException(msg, ex)
            } else {
                logger.error(msg)
            }
        }
        if (engine != null) {
            scanDependencies(engine)
            ExceptionCollection exCol = null
            logger.lifecycle("Checking for updates and analyzing dependencies for vulnerabilities")
            try {
                engine.analyzeDependencies()
            } catch (ExceptionCollection ex) {
                if (failOnError.get() || ex.isFatal()) {
                    cleanup(engine)
                    throw new GradleException("Analysis failed.", ex)
                }
                exCol = ex
            }

            logger.lifecycle("Generating report for project ${currentProjectName}")
            try {
                String name = project.getName()
                String displayName = project.getDisplayName()
                String groupId = project.getGroup()
                String version = project.getVersion().toString()
                File output = outputDir.get().asFile
                for (String f : getReportFormats(format.get(), formats.get())) {
                    engine.writeReports(displayName, groupId, name, version, output, f, exCol)
                }
                showSummary(engine)
                def result = checkForFailure(engine)
                sendSlackNotification(result)
                if (result.failed) {
                    throw new GradleException(result.msg)
                }
            } catch (ReportException ex) {
                if (failOnError.get()) {
                    if (exCol != null) {
                        exCol.addException(ex)
                        throw new GradleException("Error generating the report", exCol)
                    } else {
                        throw new GradleException("Error generating the report", ex)
                    }
                } else {
                    logger.error("Error generating the report", ex)
                }
            } finally {
                cleanup(engine)
            }
            if (failOnError.get() && exCol != null && exCol.getExceptions().size() > 0) {
                throw new GradleException("One or more exceptions occurred during analysis", exCol)
            }
        }
    }

    /**
     * Verifies aspects of the configuration to ensure dependency-check can run correctly.
     */
    def verifySettings() {
        if (!scanDependencies.get() && !scanBuildEnv.get()) {
            throw new IllegalArgumentException("At least one of scanDependencies or scanBuildEnv must be set to true")
        }
        if (!scanConfigurations.get().isEmpty() && !skipConfigurations.get().isEmpty()) {
            throw new IllegalArgumentException("you can only specify one of scanConfigurations or skipConfigurations")
        }
        if (!scanProjects.get().isEmpty() && !skipProjects.get().isEmpty()) {
            throw new IllegalArgumentException("you can only specify one of scanProjects or skipProjects")
        }
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private static Set<String> getReportFormats(String format, List<String> formats) {
        Set<String> selectedFormats = new HashSet<>()
        if (formats != null && !formats.isEmpty()) {
            for (String f : formats) {
                addFormat(f, selectedFormats)
            }
        }
        addFormat(format, selectedFormats)
        return selectedFormats
    }

    private static void addFormat(String format, Set<String> selectedFormats) {
        if (format != null && !format.trim().isEmpty()) {
            for (Format f : Format.values()) {
                if (f.toString().equalsIgnoreCase(format)) {
                    selectedFormats.add(f.toString())
                    return
                }
            }
            //could be a custom report template...
            selectedFormats.add(format)
        }
    }

    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup(Engine engine) {
        if (engine != null) {
            engine.close()
        }
        if (settings != null) {
            settings.cleanup(true)
        }
    }

    /**
     * Loads the projects dependencies into the dependency-check analysis engine.
     */
    abstract scanDependencies(Engine engine)

    /**
     * Displays a summary of the dependency-check results to the build console.
     */
    def showSummary(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.warn("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
        if (showSummary.get()) {
            DependencyCheckScanAgent.showSummary(project.name, engine.getDependencies())
        }
    }

    /**
     * If configured, fails the build if a vulnerability is identified with a CVSS
     * score higher than the failure threshold configured.
     */
    CheckForFailureResult checkForFailure(Engine engine) {
        if (failBuildOnCVSS.get() > 10) {
            return CheckForFailureResult.createSuccess()
        }

        Set<String> vulnerabilities = new HashSet<>()
        for (Dependency d : engine.getDependencies()) {
            for (Vulnerability v : d.getVulnerabilities()) {
                final double cvssV2 = v.getCvssV2() != null && v.getCvssV2().getCvssData() != null
                        && v.getCvssV2().getCvssData().getBaseScore() != null ? v.getCvssV2().getCvssData().getBaseScore() : -1
                final double cvssV3 = v.getCvssV3() != null && v.getCvssV3().getCvssData() != null
                        && v.getCvssV3().getCvssData().getBaseScore() != null ? v.getCvssV3().getCvssData().getBaseScore() : -1
                final double cvssV4 = v.getCvssV4() != null && v.getCvssV4().getCvssData() != null
                        && v.getCvssV4().getCvssData().getBaseScore() != null ? v.getCvssV4().getCvssData().getBaseScore() : -1
                final boolean useUnscored = cvssV2 == -1 && cvssV3 == -1 && cvssV4 == -1
                final double unscoredCvss = (useUnscored && v.getUnscoredSeverity() != null) ? SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) : -1
                if (cvssV2 >= failBuildOnCVSS.get()
                        || cvssV3 >= failBuildOnCVSS.get()
                        || cvssV4 >= failBuildOnCVSS.get()
                        || useUnscored && unscoredCvss >= failBuildOnCVSS.get()
                        //safety net to fail on any if for some reason the above misses on 0
                        || (failBuildOnCVSS.get() <= 0.0f)) {
                    vulnerabilities.add(v.getName())
                }
            }
        }

        if (vulnerabilities.size() > 0) {
            final String msg = String.format("%n%nDependency-Analyze Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater than '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", failBuildOnCVSS.get(), vulnerabilities.join(", "))
            return CheckForFailureResult.createFailed(msg)
        } else {
            return CheckForFailureResult.createSuccess()
        }
    }

    void sendSlackNotification(CheckForFailureResult checkForFailureResult) {
        if (checkForFailureResult.failed) {
            new SlackNotificationSenderService(settings).send(getCurrentProjectName(), checkForFailureResult.msg)
        }
    }

    def static class CheckForFailureResult {
        private Boolean failed
        private String msg

        CheckForFailureResult(Boolean failed, String msg) {
            this.failed = failed
            this.msg = msg
        }

        static CheckForFailureResult createSuccess() {
            return new CheckForFailureResult(false, "")
        }

        static CheckForFailureResult createFailed(String msg) {
            return new CheckForFailureResult(true, msg)
        }
    }

    /**
     * Whether or not to process the given project given the plugin's configuration
     */
    protected shouldProcess(Project project) {
        shouldBeScanned(project) && !shouldBeSkipped(project)
    }

    /**
     * Whether or not to process the given configuration, given the plugin's configuration
     */
    protected shouldProcess(Configuration configuration) {
        configuration.canBeResolved
                && shouldBeScanned(configuration)
                && !(shouldBeSkipped(configuration) || shouldBeSkippedAsTest(configuration))
    }

    /**
     * Resolve name for the configuration in way that works for Gradle < 8 using dynamic dispatch. The property/method
     * has moved to the Named interface in Gradle 8.0, so resolving statically breaks on Gradle 7.x.
     */
    @CompileDynamic
    private static nameOf(Configuration configuration) {
        configuration.name
    }

    /**
     * Checks whether the given project should be scanned
     * because either scanProjects is empty or it contains the
     * project's path.
     */
    private shouldBeScanned(Project project) {
        scanProjects.get().isEmpty() || scanProjects.get().contains(project.path)
    }

    /**
     * Checks whether the given project should be skipped
     * because skipProjects contains the project's path.
     */
    private shouldBeSkipped(Project project) {
        skipProjects.get().contains(project.path)
    }

    /**
     * Checks whether the given configuration should be scanned
     * because either scanConfigurations is empty or it contains the
     * configuration's name.
     */
    private shouldBeScanned(Configuration configuration) {
        scanConfigurations.get().isEmpty() || scanConfigurations.get().contains(nameOf(configuration))
    }

    /**
     * Checks whether the given configuration should be skipped
     * because skipConfigurations contains the configuration's name.
     */
    private shouldBeSkipped(Configuration configuration) {
        skipConfigurations.get().contains(nameOf(configuration))
    }

    /**
     * Checks whether the given artifact should be skipped
     * because skipGroups contains the artifact's group prefix.
     */
    private shouldBeSkipped(ResolvedArtifactResult artifact) {
        def name = artifact.id.componentIdentifier.displayName
        skipGroups.get().any { name.startsWith(it) }
    }

    /**
     * Checks whether the given configuration should be skipped
     * because it is a test configuration and skipTestGroups is true.
     */
    private shouldBeSkippedAsTest(Configuration configuration) {
        skipTestGroups.get() && isTestConfiguration(configuration)
    }

    /**
     * Determines if the configuration should be considered a test configuration.
     * @param configuration the configuration to inspect
     * @return true if the configuration is considered a test configuration; otherwise false
     */
    private isTestConfiguration(Configuration configuration) {
        def isTestConfiguration = isTestConfigurationCheck(configuration)

        def hierarchy = configuration.hierarchy.collect { nameOf(it) }.join(" --> ")
        logger.info("'{}' is considered a test configuration: {}", hierarchy, isTestConfiguration)

        isTestConfiguration
    }

    /**
     * Checks whether a configuration is considered to be a test configuration in order to skip it.
     * A configuration is considered a test configuration if and only if any of the following conditions holds:
     * <ul>
     *     <li>the name of the configuration or any of its parent configurations contains a match for /((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/</li>
     * </ul>
     * The intent of the regular expression is to match `test` in a camel case or snake case configuration name.
     */
    private static isTestConfigurationCheck(Configuration configuration) {
        boolean isTestConfiguration = nameOf(configuration) =~ TEST_CONFIG_PATTERN
        configuration.hierarchy.each {
            isTestConfiguration |= (nameOf(it) =~ TEST_CONFIG_PATTERN) as boolean
        }
        isTestConfiguration
    }

    /**
     * Resolves the Maven POM file for a given module component.
     * Uses caching to avoid redundant network calls.
     * @param project the project context
     * @param mci the module component identifier
     * @return the resolved POM file, or null if resolution fails
     */
    private File resolvePomFor(Project project, ModuleComponentIdentifier mci) {
        if (pomCache.containsKey(mci)) {
            return pomCache.get(mci)
        }
        try {
            def query = project.dependencies.createArtifactResolutionQuery()
                    .forComponents(mci)
                    .withArtifacts(MavenModule, MavenPomArtifact)
                    .execute()

            for (ComponentArtifactsResult comp : query.resolvedComponents) {
                for (def ar : comp.getArtifacts(MavenPomArtifact)) {
                    if (ar instanceof ResolvedArtifactResult) {
                        File pomFile = ((ResolvedArtifactResult) ar).getFile()
                        pomCache.put(mci, pomFile)
                        logger.debug("Resolved POM for ${mci}: ${pomFile}")
                        return pomFile
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("POM resolution failed for ${mci}: ${e.message}")
        }
        pomCache.put(mci, null)
        return null
    }

    /**
     * Process the incoming artifacts for the given project's configurations.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    protected void processBuildEnvironment(Project project, Engine engine) {
        project.getBuildscript().configurations.matching(this.&shouldProcess).toList().each { Configuration configuration ->
            processConfig project, configuration, engine, true
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    protected void processConfigurations(Project project, Engine engine) {
        project.configurations.matching(this.&shouldProcess).toList().each { Configuration configuration ->
            processConfig project, configuration, engine, false
        }
        if (!defaults.isScanSetConfigured()) {
            List<String> toScan = ['src/main/resources', 'src/main/webapp',
                                   './package.json', './package-lock.json',
                                   './npm-shrinkwrap.json', './yarn.lock',
                                   './pnpm.lock', 'pnpm-lock.yaml', './Gopkg.lock', './go.mod']
            toScan.each {
                File f = project.file it
                if (f.exists()) {
                    engine.scan(f, project.name)
                }
            }
        } else {
            defaults.scanSet.each {
                File f = project.file it
                if (f.exists()) {
                    engine.scan(f, project.name)
                } else {
                    logger.warn("ScanSet file `${f}` does not exist in ${project.name}")
                }
            }
        }

        defaults.additionalCpes.each {
            def dependency = new Dependency(true)
            dependency.setDescription(it.description.getOrNull())
            dependency.setDisplayFileName(it.cpe.getOrNull())
            dependency.setSha1sum(Checksum.getSHA1Checksum(it.cpe.getOrNull()))
            dependency.setSha256sum(Checksum.getSHA256Checksum(it.cpe.getOrNull()))
            dependency.setMd5sum(Checksum.getMD5Checksum(it.cpe.getOrNull()))
            dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier(CpeParser.parse(it.cpe.getOrNull()), Confidence.HIGHEST))
            dependency.setFileName("")
            dependency.setActualFilePath("")
            engine.addDependency(dependency)
        }
    }

    private static Map<PackageURL, Set<IncludedByReference>> buildIncludedByMap(Project project, Configuration configuration, boolean scanningBuildEnv) {
        Map<PackageURL, Set<IncludedByReference>> includedByMap = new HashMap<>()
        String type = null
        if (scanningBuildEnv) {
            type = 'buildEnv'
        }
        IncludedByReference parent = new IncludedByReference(convertIdentifier(project).toString(), type)
        configuration.incoming.resolutionResult.root.getDependencies().forEach({
            if (it instanceof ResolvedDependencyResult) {
                ResolvedComponentResult current = it.selected
                PackageURL purl = convertIdentifier(current)
                if (includedByMap.containsKey(purl)) {
                    includedByMap.get(purl).add(parent)
                } else {
                    Set<IncludedByReference> rootParent = new HashSet<>()
                    rootParent.add(parent)
                    includedByMap.put(purl, rootParent)
                }
                IncludedByReference root = new IncludedByReference(convertIdentifier(current).toString(), type)
                collectDependencyMap(includedByMap, root, current.getDependencies(), 0)
            } else {
                //TODO logging?
            }
        })
        return includedByMap
    }

    private static void collectDependencyMap(Map<PackageURL, Set<IncludedByReference>> includedByMap, IncludedByReference root, Set<? extends DependencyResult> dependencies, int depth) {
        for (DependencyResult it : dependencies) {
            if (it instanceof ResolvedDependencyResult) {
                ResolvedComponentResult current = it.selected
                PackageURL purl = convertIdentifier(current)
                if (includedByMap.containsKey(purl)) {
                    // jackson-bom ends up creating an infinite loop so check if we've been here before
                    // https://github.com/dependency-check/dependency-check-gradle/issues/307
                    Set<IncludedByReference> includedBy = includedByMap.get(purl)
                    if (includedBy.contains(root)) {
                        continue
                    }
                    includedBy.add(root)
                } else {
                    Set<IncludedByReference> rootParent = new HashSet<>()
                    rootParent.add(root)
                    includedByMap.put(purl, rootParent)
                }
                if (current.getDependencies() != null && !current.getDependencies().isEmpty() && depth < 500) {
                    collectDependencyMap(includedByMap, root, current.getDependencies(), depth + 1)
                }
            }
        }
    }

    /**
     * Process the incoming artifacts for the given project's configuration.
     * @param project the project to analyze
     * @param configuration a particular configuration of the project to analyze
     * @param engine the dependency-check engine
     * @param scanningBuildEnv true if scanning the build environment; otherwise false
     */
    protected void processConfig(Project project, Configuration configuration, Engine engine, boolean scanningBuildEnv = false) {
        String scope = "${project.name}:${nameOf(configuration)}${scanningBuildEnv ? ' (buildEnv)' : ''}"
        logger.info "- Analyzing ${scope}"

        Map<String, ModuleVersionIdentifier> componentVersions = [:]
        configuration.incoming.resolutionResult.allDependencies.each {
            switch (it) {
                case ResolvedDependencyResult:
                    (it as ResolvedDependencyResult).with { componentVersions.put(selected.id.toString(), selected.moduleVersion) }
                    break
                case UnresolvedDependencyResult:
                    (it as UnresolvedDependencyResult).with { logger.debug("Unable to resolve artifact in ${attempted.displayName}") }
                    break
                default:
                    logger.warn("Unable to resolve: ${it}")
            }
        }
        Map<PackageURL, Set<IncludedByReference>> includedByMap = buildIncludedByMap(project, configuration, scanningBuildEnv)

        def types = analyzedTypes.get()
        for (String type : types) {
            List<ResolvedArtifactResult> rar = configuration.incoming.artifactView {
                it.setLenient(true)
                it.attributes { attrs ->
                    attrs.attribute(artifactType, type)
                }
            }.getArtifacts().toList()

            for (ResolvedArtifactResult resolvedArtifactResult : rar) {
                if (shouldBeSkipped(resolvedArtifactResult)) {
                    continue
                }
                ModuleVersionIdentifier id = componentVersions[resolvedArtifactResult.id.componentIdentifier.getDisplayName()]
                if (id == null) {
                    logger.debug "Could not find dependency {'artifact': '${resolvedArtifactResult.id.componentIdentifier}', " +
                            "'file':'${resolvedArtifactResult.file}'}"
                } else {
                    def deps = engine.scan(resolvedArtifactResult.file, scope)
                    if (!project.gradle.startParameter.offline && deps != null && deps.size() == 1) {
                        // Resolve and analyze POM for maven modules to extract additional evidence
                        def compId = resolvedArtifactResult.id.componentIdentifier
                        if (compId instanceof ModuleComponentIdentifier) {
                            File pomFile = resolvePomFor(project, compId)
                            if (pomFile != null) {
                                try {
                                    PomUtils.analyzePOM(deps[0], pomFile)
                                } catch (Exception e) {
                                    logger.debug("Failed to analyze POM for ${compId.group}:${compId.module}:${compId.version}: ${e}")
                                }
                            }
                        }
                    }
                    if (deps != null) {
                        addInfoToDependencies(deps, scope, id, includedByMap.get(convertIdentifier(id)))
                    }
                }
            }
        }
    }

    /**
     * Adds additional information and evidence to the dependencies.
     * @param deps the list of dependencies that will be updated
     * @param configurationName the configuration name that the artifact was identified in
     * @param group the group id for the artifact coordinates
     * @param artifact the artifact id for the artifact coordinates
     * @param version the version number for the artifact coordinates
     */
    private static void addInfoToDependencies(List<Dependency> deps, String configurationName,
                                              ModuleVersionIdentifier id, Set<IncludedByReference> includedBy) {
        if (deps != null) {
            if (deps.size() == 1) {
                def d = deps.get(0)
                MavenArtifact mavenArtifact = new MavenArtifact(id.group, id.name, id.version)
                d.addAsEvidence("gradle", mavenArtifact, Confidence.HIGHEST)
                d.addProjectReference(configurationName)
                if (includedBy != null) {
                    d.addAllIncludedBy(includedBy)
                }
            } else {
                for (Dependency it : deps) {
                    it.addProjectReference(configurationName)
                    if (includedBy != null) {
                        it.addAllIncludedBy(includedBy)
                    }
                }
            }
        }
    }

    private static PackageURL convertIdentifier(Project project) {
        final PackageURL p
        if (project.group) {
            p = new PackageURL("maven", project.group.toString(),
                    project.name, project.version.toString(), null, null)
        } else {
            p = PackageURLBuilder.aPackageURL().withType("gradle")
                    .withName(project.name).withVersion(project.version.toString()).build()
        }
        return p
    }

    private static PackageURL convertIdentifier(ResolvedComponentResult result) {
        return convertIdentifier(result.getModuleVersion())
    }

    private static PackageURL convertIdentifier(ModuleVersionIdentifier id) {
        PackageURL p
        if (id.group) {
            p = new PackageURL("maven", id.group,
                    id.name, id.version, null, null)
        } else {
            PackageURLBuilder pb = PackageURLBuilder.aPackageURL().withType("gradle")
                    .withName(id.name)
            if (id.version) {
                pb.withVersion(id.version)
            }
            p = pb.build()
        }
        return p
    }

    private void configureSlack(org.owasp.dependencycheck.utils.Settings settings) {
        settings.setBooleanIfNotNull(SlackNotificationSenderService.SLACK__WEBHOOK__ENABLED, slack.enabled.getOrNull())
        settings.setStringIfNotEmpty(SlackNotificationSenderService.SLACK__WEBHOOK__URL, slack.webhookUrl.getOrNull())
    }

    private String[] determineSuppressions(Collection<String> suppressionFiles, String suppressionFile) {
        List<String> files = []
        if (suppressionFiles != null) {
            for (String sf : suppressionFiles) {
                files.add(sf.toString())
            }
        }
        if (suppressionFile != null) {
            files.add(suppressionFile)
        }
        return files.toArray(new String[0])
    }

    private Boolean select(Boolean current, Boolean deprecated) {
        return current != null ? current : deprecated
    }
}

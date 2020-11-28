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

import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ModuleVersionIdentifier
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.attributes.Attribute
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.util.GradleVersion
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent
import org.owasp.dependencycheck.data.nexus.MavenArtifact
import org.owasp.dependencycheck.data.nvdcve.DatabaseException
import org.owasp.dependencycheck.dependency.Confidence
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.exception.ExceptionCollection
import org.owasp.dependencycheck.exception.ReportException
import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.owasp.dependencycheck.utils.SeverityUtil

import java.util.stream.Collectors

import static org.owasp.dependencycheck.dependency.EvidenceType.*
import static org.owasp.dependencycheck.reporting.ReportGenerator.Format
import static org.owasp.dependencycheck.utils.Checksum.*

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
abstract class AbstractAnalyze extends ConfiguredTask {

    @Internal
    def currentProjectName = project.getName()
    @Internal
    def artifactType = Attribute.of('artifactType', String)
    // @Internal
    private static final GradleVersion CUTOVER_GRADLE_VERSION = GradleVersion.version("4.0")
    private static final GradleVersion IGNORE_NON_RESOLVABLE_SCOPES_GRADLE_VERSION = GradleVersion.version("7.0")

    /**
     * Calls dependency-check-core's analysis engine to scan
     * all of the projects dependencies.
     */
    @TaskAction
    analyze() {
        if (config.skip) {
            logger.lifecycle("Skipping dependency-check-gradle")
            return
        }
        verifySettings()
        initializeSettings()
        def engine = null
        try {
            engine = new Engine(settings)
        } catch (DatabaseException ex) {
            String msg = "Unable to connect to the dependency-check database"
            if (config.failOnError) {
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
                if (config.failOnError || ex.isFatal()) {
                    cleanup(engine)
                    throw new GradleException("Analysis failed.", ex)
                }
                exCol = ex
            }

            logger.lifecycle("Generating report for project ${currentProjectName}")
            try {
                def name = project.getName()
                def displayName = determineDisplayName()
                def groupId = project.getGroup()
                File output = new File(config.outputDirectory)
                for (String f : getReportFormats(config.format, config.formats)) {
                    engine.writeReports(displayName, groupId, name.toString(), project.getVersion().toString(), output, f, exCol)
                }
                showSummary(engine)
                def result = checkForFailure(engine)
                sendSlackNotification(result)
                if (result.failed) {
                    throw new GradleException(result.msg)
                }
            } catch (ReportException ex) {
                if (config.failOnError) {
                    if (exCol != null) {
                        exCol.addException(ex)
                        throw new GradleException(exCol)
                    } else {
                        throw new GradleException("Error generating the report", ex)
                    }
                } else {
                    logger.error("Error generating the report", ex)
                }
            } finally {
                cleanup(engine)
            }
            if (config.failOnError && exCol != null && exCol.getExceptions().size() > 0) {
                throw new GradleException("One or more exceptions occurred during analysis", exCol)
            }
        }
    }

    /**
     * Gets the projects display name. Project.getDisplayName() has been
     * introduced with Gradle 3.3, thus we need to check for the method's
     * existence first. Fallback: use project NAME
     * @return the display name
     */
    def determineDisplayName() {
        project.metaClass.respondsTo(project, "getDisplayName") ?
                project.getDisplayName() : project.getName()
    }
    /**
     * Verifies aspects of the configuration to ensure dependency-check can run correctly.
     */
    def verifySettings() {
        if (config.scanConfigurations && config.skipConfigurations) {
            throw new IllegalArgumentException("you can only specify one of scanConfigurations or skipConfigurations")
        }
        if (config.scanProjects && config.skipProjects) {
            throw new IllegalArgumentException("you can only specify one of scanProjects or skipProjects")
        }
    }


    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private Set<Format> getReportFormats(Format format, List<Format> formats) {
        def mapFormat = { fmt -> fmt.toString() }
        Set<String> selectedFormats = formats == null || formats.isEmpty() ? new HashSet<>() :
                formats.stream().map(mapFormat).collect(Collectors.toSet());
        if (format != null && !selectedFormats.contains(format.toString())) {
            selectedFormats.add(format.toString());
        }
        return selectedFormats;
    }

    /**
     * Releases resources and removes temporary files used.
     */
    def cleanup(engine) {
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
    abstract scanDependencies(engine)

    /**
     * Displays a summary of the dependency-check results to the build console.
     */
    def showSummary(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.warn("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
        if (config.showSummary) {
            DependencyCheckScanAgent.showSummary(project.name, engine.getDependencies());
        }
    }

    /**
     * If configured, fails the build if a vulnerability is identified with a CVSS
     * score higher than the failure threshold configured.
     */
    CheckForFailureResult checkForFailure(Engine engine) {
        if (config.failBuildOnCVSS > 10) {
            return CheckForFailureResult.createSuccess()
        }

        final String vulnerabilities = engine.getDependencies()
                .collect { it.getVulnerabilities() }
                .flatten()
                .unique()
                .findAll {
                    ((it.getCvssV2() != null && it.getCvssV2().getScore() >= config.failBuildOnCVSS)
                            || (it.getCvssV3() != null && it.getCvssV3().getBaseScore() >= config.failBuildOnCVSS)
                            || (it.getUnscoredSeverity() != null && SeverityUtil.estimateCvssV2(it.getUnscoredSeverity()) >= config.failBuildOnCVSS)
                            //safety net to fail on any if for some reason the above misses on 0
                            || (config.failBuildOnCVSS<=0.0f))
                }
                .collect { it.getName() }
                .join(", ")

        if (vulnerabilities.length() > 0) {
            final String msg = String.format("%n%nDependency-Analyze Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater than '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", config.failBuildOnCVSS, vulnerabilities)
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
     * Checks whether the given project should be scanned
     * because either scanProjects is empty or it contains the
     * project's path.
     */
    def shouldBeScanned(Project project) {
        !config.scanProjects || config.scanProjects.contains(project.path)
    }

    /**
     * Checks whether the given project should be skipped
     * because skipProjects contains the project's path.
     */
    def shouldBeSkipped(Project project) {
        config.skipProjects.contains(project.path)
    }

    /**
     * Checks whether the given configuration should be scanned
     * because either scanConfigurations is empty or it contains the
     * configuration's name.
     */
    def shouldBeScanned(configuration) {
        !config.scanConfigurations || config.scanConfigurations.contains(configuration.name)
    }

    /**
     * Checks whether the given configuration should be skipped
     * because skipConfigurations contains the configuration's name.
     */
    def shouldBeSkipped(configuration) {
        ((IGNORE_NON_RESOLVABLE_SCOPES_GRADLE_VERSION.compareTo(GradleVersion.current()) <= 0 && (
            "archives".equals(configuration.name) ||
            "default".equals(configuration.name) ||
            "runtime".equals(configuration.name) ||
            "compile".equals(configuration.name) ||
            "compileOnly".equals(configuration.name)))
        || config.skipConfigurations.contains(configuration.name))
    }

    /**
     * Checks whether the given configuration should be skipped
     * because it is a test configuration and skipTestGroups is true.
     */
    def shouldBeSkippedAsTest(configuration) {
        config.skipTestGroups && isTestConfiguration(configuration)
    }

    /**
     * Determines if the configuration should be considered a test configuration.
     * @param configuration the configuration to insepct
     * @return true if the configuration is considered a tet configuration; otherwise false
     */
    def isTestConfiguration(configuration) {
        def isTestConfiguration = isTestConfigurationCheck(configuration)

        def hierarchy = configuration.hierarchy.collect({ it.name }).join(" --> ")
        logger.info("'{}' is considered a test configuration: {}", hierarchy, isTestConfiguration)

        isTestConfiguration
    }

    /**
     * Checks whether a configuration is considered to be a test configuration in order to skip it.
     * A configuration is considered a test configuration if and only if any of the following conditions holds:
     * <ul>
     *     <li>the name of the configuration or any of its parent configurations equals 'testCompile'</li>
     *     <li>the name of the configuration or any of its parent configurations equals 'androidTestCompile'</li>
     *     <li>the configuration name starts with 'test'</li>
     *     <li>the configuration name starts with 'androidTest'</li>
     * </ul>
     */
    static isTestConfigurationCheck(configuration) {
        def isTestConfiguration = configuration.name.startsWith("test") || configuration.name.startsWith("androidTest")
        configuration.hierarchy.each {
            isTestConfiguration |= (it.name == "testCompile" || it.name == "androidTestCompile")
        }
        isTestConfiguration
    }

    /**
     * Determines if the onfiguration can be resolved
     * @param configuration the configuration to inspect
     * @return true if the configuration can be resolved; otherwise false
     */
    def canBeResolved(configuration) {
        configuration.metaClass.respondsTo(configuration, "isCanBeResolved") ?
                configuration.isCanBeResolved() : true
    }

    /**
     * Process the incoming artifacts for the given project's configurations.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    protected void processConfigurations(Project project, Engine engine) {
        project.configurations.findAll { Configuration configuration ->
            shouldBeScanned(configuration) && !(shouldBeSkipped(configuration)
                    || shouldBeSkippedAsTest(configuration)) && canBeResolved(configuration)
        }.each { Configuration configuration ->
            if (CUTOVER_GRADLE_VERSION.compareTo(GradleVersion.current()) > 0) {
                processConfigLegacy configuration, engine
            } else {
                processConfigV4 project, configuration, engine
            }
        }
        boolean customScanSet = false
        List<String> toScan = ['src/main/resources', 'src/main/webapp',
                               './package.json', './package-lock.json',
                               './npm-shrinkwrap.json', './Gopkg.lock', './go.mod']
        if (config.scanSet != null) {
            toScan = config.scanSet
            customScanSet = true
        }
        toScan.each {
            File f = project.file it
            if (f.exists()) {
                engine.scan(f, project.name)
            } else if (customScanSet) {
                logger.warn("ScanSet file `${it}` does not exist in ${project.name}")
            }
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations using APIs pre-gradle 4.0.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    protected void processConfigLegacy(Configuration configuration, Engine engine) {
        configuration.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
            def dependencies = engine.scan(artifact.getFile())
            addInfoToDependencies(dependencies, configuration.name,
                    artifact.moduleVersion.id.group,
                    artifact.moduleVersion.id.name,
                    artifact.moduleVersion.id.version)
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations using APIs introduced in gradle 4.0+.
     * @param project the project to analyze
     * @param configuration a particular configuration of the project to analyze
     * @param engine the dependency-check engine
     */
    protected void processConfigV4(Project project, Configuration configuration, Engine engine) {
        String projectName = project.name
        String scope = "$projectName:$configuration.name"

        logger.info "- Analyzing ${scope}"

        Map<String, ModuleVersionIdentifier> componentVersions = [:]
        configuration.incoming.resolutionResult.allDependencies.each {
            if (it.hasProperty('selected')) {
                componentVersions.put(it.selected.id, it.selected.moduleVersion)
            } else if (it.hasProperty('attempted')) {
                logger.debug("Unable to resolve artifact in ${it.attempted.displayName}")
            } else {
                logger.warn("Unable to resolve: ${it}")
            }
        }

        def types = config.analyzedTypes

        types.each { type ->
            configuration.incoming.artifactView {
                lenient true
                attributes {
                    it.attribute(artifactType, type)
                }
            }.artifacts.each {
                def deps = engine.scan(it.file, scope)
                ModuleVersionIdentifier id = componentVersions[it.id.componentIdentifier]
                if (id == null) {
                    logger.debug "Could not find dependency {'artifact': '${it.id.componentIdentifier}', " +
                            "'file':'${it.file}'}"
                } else {
                    if (deps == null) {
                        if (it.file.isFile()) {
                            addDependency(engine, projectName, configuration.name,
                                    id.group, id.name, id.version, it.id.displayName, it.file)
                        } else {
                            addDependency(engine, projectName, configuration.name,
                                    id.group, id.name, id.version, it.id.displayName)
                        }
                    } else {
                        addInfoToDependencies(deps, scope, id.group, id.name, id.version)
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
    protected void addInfoToDependencies(List<Dependency> deps, String configurationName,
                                         String group, String artifact, String version) {
        if (deps != null) {
            if (deps.size() == 1) {
                def d = deps.get(0)
                MavenArtifact mavenArtifact = new MavenArtifact(group, artifact, version)
                d.addAsEvidence("gradle", mavenArtifact, Confidence.HIGHEST)
                //if (group != null && artifact != null && version != null) {
                //    d.addIdentifier("maven", String.format("%s:%s:%s", group, artifact, version), null, Confidence.HIGHEST)
                //}
                d.addProjectReference(configurationName)
            } else {
                deps.forEach { it.addProjectReference(configurationName) }
            }
        }
    }

    /**
     * Adds a dependency to the engine. This is used when an artifact is scanned that is not
     * supported by dependency-check (different dependency type for possibly new language).
     * @param engine a reference to the engine
     * @param projectName the project name
     * @param configurationName the configuration name
     * @param group the group id
     * @param name the name or artifact id
     * @param version the version number
     * @param displayName the display name
     */
    protected void addDependency(Engine engine, String projectName, String configurationName,
                                 String group, String name, String version, String displayName,
                                 File file = null) {

        def display = displayName ?: "${group}:${name}:${version}"
        Dependency dependency
        String sha256
        if (file == null) {
            logger.debug("Adding virtual dependency for ${display}")
            dependency = new Dependency(new File(project.buildDir.getParentFile(), "build.gradle"), true)
            sha256 = getSHA256Checksum("${group}:${name}:${version}")
        } else {
            logger.debug("Adding dependency for ${display}")
            dependency = new Dependency(file)
            sha256 = dependency.getSha256sum()
        }

        def existing = engine.dependencies.find {
            sha256.equals(it.getSha256sum())
        }
        if (existing != null) {
            existing.addProjectReference("${projectName}:${configurationName}")
        } else {
            if (dependency.virtual) {
                dependency.sha1sum = getSHA1Checksum("${group}:${name}:${version}")
                dependency.sha256sum = sha256
                dependency.md5sum = getMD5Checksum("${group}:${name}:${version}")
                dependency.displayFileName = display
            }
            dependency.addEvidence(VENDOR, "build.gradle", "group", group, Confidence.HIGHEST)
            dependency.addEvidence(VENDOR, "build.gradle", "name", name, Confidence.MEDIUM)
            dependency.addEvidence(VENDOR, "build.gradle", "displayName", display, Confidence.MEDIUM)
            dependency.addEvidence(PRODUCT, "build.gradle", "group", group, Confidence.MEDIUM)
            dependency.addEvidence(PRODUCT, "build.gradle", "name", name, Confidence.HIGHEST)
            dependency.addEvidence(PRODUCT, "build.gradle", "displayName", display, Confidence.HIGH)
            dependency.addEvidence(VERSION, "build.gradle", "version", version, Confidence.HIGHEST)
            dependency.name = name
            dependency.version = version
            dependency.packagePath = "${group}:${name}:${version}"
            dependency.addProjectReference("${projectName}:${configurationName}")
            if (file != null && file.getName().endsWith(".aar")) {
                dependency.ecosystem = "android"
            } else {
                dependency.ecosystem = "gradle"
            }
            //dependency.addIdentifier("maven", "${group}:${name}:${version}", null, Confidence.HIGHEST)

            engine.addDependency(dependency)
        }
    }
}

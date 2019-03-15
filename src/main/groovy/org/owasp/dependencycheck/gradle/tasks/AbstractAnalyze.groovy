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

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.InvalidUserDataException
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ModuleVersionIdentifier
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.attributes.Attribute
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.util.GradleVersion
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nexus.MavenArtifact
import org.owasp.dependencycheck.data.nvdcve.DatabaseException
import org.owasp.dependencycheck.dependency.Confidence
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.exception.ExceptionCollection
import org.owasp.dependencycheck.exception.ReportException
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.dependency.EvidenceType.*
import static org.owasp.dependencycheck.utils.Checksum.*
import static org.owasp.dependencycheck.utils.Settings.KEYS.*

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
abstract class AbstractAnalyze extends DefaultTask {

    @Internal
    def currentProjectName = project.getName()
    @Internal
    def config = project.dependencyCheck
    @Internal
    def settings
    @Internal
    def PROPERTIES_FILE = "task.properties"
    @Internal
    def artifactType = Attribute.of('artifactType', String)
    @Internal
    static final GradleVersion CUTOVER_GRADLE_VERSION = GradleVersion.version("4.0")



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
                if (config.failOnError && ex.isFatal()) {
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
                engine.writeReports(displayName, groupId, name.toString(), project.getVersion().toString(), output,
                        config.format.toString())
                showSummary(engine)
                checkForFailure(engine)
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
     * Initializes the settings object. If the setting is not set the
     * default from dependency-check-core is used.
     */
    def initializeSettings() {
        settings = new Settings()

        InputStream taskProperties = null
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE)
            settings.mergeProperties(taskProperties)
        } catch (IOException ex) {
            logger.warn("Unable to load the dependency-check gradle task.properties file.")
            logger.debug("", ex)
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close()
                } catch (IOException ex) {
                    logger.debug("", ex)
                }
            }
        }
        settings.setBooleanIfNotNull(AUTO_UPDATE, config.autoUpdate)

        String[] suppressionLists = determineSuppressions(config.suppressionFiles, config.suppressionFile)

        settings.setArrayIfNotEmpty(SUPPRESSION_FILE, suppressionLists)
        settings.setStringIfNotEmpty(HINTS_FILE, config.hintsFile)

        settings.setStringIfNotEmpty(PROXY_SERVER, config.proxy.server)
        settings.setStringIfNotEmpty(PROXY_PORT, "${config.proxy.port}")
        settings.setStringIfNotEmpty(PROXY_USERNAME, config.proxy.username)
        settings.setStringIfNotEmpty(PROXY_PASSWORD, config.proxy.password)
        //settings.setStringIfNotEmpty(CONNECTION_TIMEOUT, connectionTimeout)
        settings.setStringIfNotNull(DATA_DIRECTORY, config.data.directory)
        settings.setStringIfNotEmpty(DB_DRIVER_NAME, config.data.driver)
        settings.setStringIfNotEmpty(DB_DRIVER_PATH, config.data.driverPath)
        settings.setStringIfNotEmpty(DB_CONNECTION_STRING, config.data.connectionString)
        settings.setStringIfNotEmpty(DB_USER, config.data.username)
        settings.setStringIfNotEmpty(DB_PASSWORD, config.data.password)
        settings.setStringIfNotEmpty(CVE_MODIFIED_JSON, config.cve.urlModified)
        settings.setStringIfNotEmpty(CVE_BASE_JSON, config.cve.urlBase)
        settings.setBooleanIfNotNull(DOWNLOADER_QUICK_QUERY_TIMESTAMP, config.quickQueryTimestamp)

        if (config.cveValidForHours != null) {
            if (config.cveValidForHours >= 0) {
                settings.setInt(CVE_CHECK_VALID_FOR_HOURS, config.cveValidForHours)
            } else {
                throw new InvalidUserDataException("Invalid setting: `validForHours` must be 0 or greater")
            }
        }
        settings.setBooleanIfNotNull(ANALYZER_JAR_ENABLED, config.analyzers.jarEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUSPEC_ENABLED, config.analyzers.nuspecEnabled)
        settings.setBooleanIfNotNull(ANALYZER_CENTRAL_ENABLED, config.analyzers.centralEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NEXUS_ENABLED, config.analyzers.nexusEnabled)
        settings.setStringIfNotEmpty(ANALYZER_NEXUS_URL, config.analyzers.nexusUrl)
        settings.setBooleanIfNotNull(ANALYZER_NEXUS_USES_PROXY, config.analyzers.nexusUsesProxy)

        settings.setBooleanIfNotNull(ANALYZER_EXPERIMENTAL_ENABLED, config.analyzers.experimentalEnabled)
        settings.setBooleanIfNotNull(ANALYZER_ARCHIVE_ENABLED, config.analyzers.archiveEnabled)
        settings.setStringIfNotEmpty(ADDITIONAL_ZIP_EXTENSIONS, config.analyzers.zipExtensions)
        settings.setBooleanIfNotNull(ANALYZER_ASSEMBLY_ENABLED, config.analyzers.assemblyEnabled)
        settings.setStringIfNotEmpty(ANALYZER_ASSEMBLY_DOTNET_PATH, config.analyzers.pathToDotnet)

        settings.setBooleanIfNotNull(ANALYZER_COCOAPODS_ENABLED, config.analyzers.cocoapodsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, config.analyzers.swiftEnabled)
        settings.setBooleanIfNotNull(ANALYZER_BUNDLE_AUDIT_ENABLED, config.analyzers.bundleAuditEnabled)
        settings.setStringIfNotEmpty(ANALYZER_BUNDLE_AUDIT_PATH, config.analyzers.pathToBundleAudit)

        settings.setBooleanIfNotNull(ANALYZER_PYTHON_DISTRIBUTION_ENABLED, config.analyzers.pyDistributionEnabled)
        settings.setBooleanIfNotNull(ANALYZER_PYTHON_PACKAGE_ENABLED, config.analyzers.pyPackageEnabled)
        settings.setBooleanIfNotNull(ANALYZER_RUBY_GEMSPEC_ENABLED, config.analyzers.rubygemsEnabled)
        settings.setBooleanIfNotNull(ANALYZER_OPENSSL_ENABLED, config.analyzers.opensslEnabled)
        settings.setBooleanIfNotNull(ANALYZER_CMAKE_ENABLED, config.analyzers.cmakeEnabled)
        settings.setBooleanIfNotNull(ANALYZER_AUTOCONF_ENABLED, config.analyzers.autoconfEnabled)
        settings.setBooleanIfNotNull(ANALYZER_COMPOSER_LOCK_ENABLED, config.analyzers.composerEnabled)
        settings.setBooleanIfNotNull(ANALYZER_NUGETCONF_ENABLED, config.analyzers.nugetconfEnabled)

        settings.setBooleanIfNotNull(ANALYZER_NODE_PACKAGE_ENABLED, config.analyzers.nodeEnabled)
        if (config.analyzers.nspEnabled != null) {
            logger.error("The nspAnalyzerEnabled configuration has been deprecated and replaced by nodeAuditAnalyzerEnabled");
            logger.error("The nspAnalyzerEnabled configuration will be removed in the next major release");
            settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, config.analyzers.nspEnabled);
        }
        settings.setBooleanIfNotNull(ANALYZER_NODE_AUDIT_ENABLED, config.analyzers.nodeAuditEnabled);

        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_ENABLED, config.analyzers.retirejs.enabled)
        settings.setBooleanIfNotNull(ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, config.analyzers.retirejs.filterNonVulnerable)
        settings.setArrayIfNotEmpty(ANALYZER_RETIREJS_FILTERS, config.analyzers.retirejs.filters)

        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_ENABLED, config.analyzers.artifactory.enabled)
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, config.analyzers.artifactory.parallelAnalysis)
        settings.setBooleanIfNotNull(ANALYZER_ARTIFACTORY_USES_PROXY, config.analyzers.artifactory.usesProxy)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_URL, config.analyzers.artifactory.url)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_TOKEN, config.analyzers.artifactory.apiToken)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_API_USERNAME, config.analyzers.artifactory.username)
        settings.setStringIfNotNull(ANALYZER_ARTIFACTORY_BEARER_TOKEN, config.analyzers.artifactory.bearerToken)

    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions(suppressionFiles, suppressionFile) {
        if (suppressionFile != null) {
            suppressionFiles << suppressionFile
        }
        suppressionFiles
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
     * score higher then the failure threshold configured.
     */
    def checkForFailure(Engine engine) {
        if (config.failBuildOnCVSS > 10) {
            return
        }

        final String vulnerabilities = engine.getDependencies()
                .collect { it.getVulnerabilities() }
                .flatten()
                .unique()
                .findAll { ((it.getCvssV2() != null && it.getCvssV2().getScore() >= config.failBuildOnCVSS)
                        || (it.getCvssV3() != null && it.getCvssV3().getBaseScore() >= config.failBuildOnCVSS))}
                .collect { it.getName() }
                .join(", ")

        if (vulnerabilities.length() > 0) {
            final String msg = String.format("%n%nDependency-Analyze Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater then '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", config.failBuildOnCVSS, vulnerabilities)
            throw new GradleException(msg)
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
        config.skipConfigurations.contains(configuration.name)
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
        List<String> toScan = ['src/main/resources','src/main/webapp']
        if (config.scanSet != null) {
            toScan = config.scanSet
            customScanSet = true
        }
        toScan.each {
            File f  = project.file it
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

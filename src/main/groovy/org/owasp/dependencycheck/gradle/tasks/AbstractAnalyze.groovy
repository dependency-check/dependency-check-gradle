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
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ModuleVersionIdentifier
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ComponentArtifactsResult
import org.gradle.api.artifacts.result.DependencyResult
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.ResolvedComponentResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.maven.MavenModule
import org.gradle.maven.MavenPomArtifact
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
import org.owasp.dependencycheck.dependency.IncludedByReference
import org.owasp.dependencycheck.dependency.Vulnerability
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier
import org.owasp.dependencycheck.exception.ExceptionCollection
import org.owasp.dependencycheck.exception.ReportException
import org.owasp.dependencycheck.gradle.service.SlackNotificationSenderService
import org.owasp.dependencycheck.utils.SeverityUtil
import org.owasp.dependencycheck.utils.Checksum
import org.owasp.dependencycheck.xml.pom.PomUtils
import us.springett.parsers.cpe.CpeParser

import static org.owasp.dependencycheck.dependency.EvidenceType.PRODUCT
import static org.owasp.dependencycheck.dependency.EvidenceType.VENDOR
import static org.owasp.dependencycheck.reporting.ReportGenerator.Format
import static org.owasp.dependencycheck.utils.Checksum.*

/**
 * Checks the projects dependencies for known vulnerabilities.
 */
//@groovy.transform.CompileStatic
abstract class AbstractAnalyze extends ConfiguredTask {

    @Internal
    String currentProjectName = project.getName()
    @Internal
    Attribute artifactType = Attribute.of('artifactType', String)
    // @Internal
    private static final GradleVersion CUTOVER_GRADLE_VERSION = GradleVersion.version("4.0")
    private static final GradleVersion IGNORE_NON_RESOLVABLE_SCOPES_GRADLE_VERSION = GradleVersion.version("7.0")

    private final Map<ModuleComponentIdentifier, File> pomCache = new HashMap<>()

    /**
     * Calls dependency-check-core's analysis engine to scan
     * all of the projects dependencies.
     */
    @TaskAction
    @groovy.transform.CompileStatic
    analyze() {
        if (config.skip.get()) {
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
            if (config.failOnError.get()) {
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
                if (config.failOnError.get() || ex.isFatal()) {
                    cleanup(engine)
                    throw new GradleException("Analysis failed.", ex)
                }
                exCol = ex
            }

            logger.lifecycle("Generating report for project ${currentProjectName}")
            try {
                String name = project.getName()
                String displayName = determineDisplayName()
                String groupId = project.getGroup()
                String version = project.getVersion().toString()
                File output = config.outputDirectory.get().asFile
                for (String f : getReportFormats(config.format.get(), config.formats.get())) {
                    engine.writeReports(displayName, groupId, name, version, output, f, exCol)
                }
                showSummary(engine)
                def result = checkForFailure(engine)
                sendSlackNotification(result)
                if (result.failed) {
                    throw new GradleException(result.msg)
                }
            } catch (ReportException ex) {
                if (config.failOnError.get()) {
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
            if (config.failOnError.get() && exCol != null && exCol.getExceptions().size() > 0) {
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
    String determineDisplayName() {
        return project.metaClass.respondsTo(project, "getDisplayName") ? project.getDisplayName() : project.getName()
    }
    /**
     * Verifies aspects of the configuration to ensure dependency-check can run correctly.
     */
    @groovy.transform.CompileStatic
    def verifySettings() {
        if (!config.scanDependencies.get() && !config.scanBuildEnv.get()) {
            throw new IllegalArgumentException("At least one of scanDependencies or scanBuildEnv must be set to true")
        }
        if (!config.scanConfigurations.get().isEmpty() && !config.skipConfigurations.get().isEmpty()) {
            throw new IllegalArgumentException("you can only specify one of scanConfigurations or skipConfigurations")
        }
        if (!config.scanProjects.get().isEmpty() && !config.skipProjects.get().isEmpty()) {
            throw new IllegalArgumentException("you can only specify one of scanProjects or skipProjects")
        }
    }


    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    @groovy.transform.CompileStatic
    private Set<String> getReportFormats(String format, List<String> formats) {
        Set<String> selectedFormats = new HashSet<>();
        if (formats != null && !formats.isEmpty()) {
            for (String f : formats) {
                addFormat(f, selectedFormats)
            }
        }
        addFormat(format, selectedFormats)
        return selectedFormats;
    }

    @groovy.transform.CompileStatic
    private void addFormat(String format, HashSet<String> selectedFormats) {
        if (format != null && !format.trim().isEmpty()) {
            for (Format f : Format.values()) {
                if (f.toString().equalsIgnoreCase(format)) {
                    selectedFormats.add(f.toString())
                    return;
                }
            }
            //could be a custom report template...
            selectedFormats.add(format);
        }
    }

    /**
     * Releases resources and removes temporary files used.
     */
    @groovy.transform.CompileStatic
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
    @groovy.transform.CompileStatic
    def showSummary(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.warn("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
        if (config.showSummary.get()) {
            DependencyCheckScanAgent.showSummary(project.name, engine.getDependencies());
        }
    }

    /**
     * If configured, fails the build if a vulnerability is identified with a CVSS
     * score higher than the failure threshold configured.
     */
    @groovy.transform.CompileStatic
    CheckForFailureResult checkForFailure(Engine engine) {
        if (config.failBuildOnCVSS.get() > 10) {
            return CheckForFailureResult.createSuccess()
        }

        Set<String> vulnerabilities = new HashSet<>();
        for (Dependency d : engine.getDependencies()) {
            for (Vulnerability v : d.getVulnerabilities()) {
                final double cvssV2 = v.getCvssV2() != null && v.getCvssV2().getCvssData() != null
                        && v.getCvssV2().getCvssData().getBaseScore() != null ? v.getCvssV2().getCvssData().getBaseScore() : -1;
                final double cvssV3 = v.getCvssV3() != null && v.getCvssV3().getCvssData() != null
                        && v.getCvssV3().getCvssData().getBaseScore() != null ? v.getCvssV3().getCvssData().getBaseScore() : -1;
                final double cvssV4 = v.getCvssV4() != null && v.getCvssV4().getCvssData() != null
                        && v.getCvssV4().getCvssData().getBaseScore() != null ? v.getCvssV4().getCvssData().getBaseScore() : -1;
                final boolean useUnscored = cvssV2 == -1 && cvssV3 == -1 && cvssV4 == -1;
                final double unscoredCvss = (useUnscored && v.getUnscoredSeverity() != null) ? SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) : -1;
                if (cvssV2 >= config.failBuildOnCVSS.get()
                        || cvssV3 >= config.failBuildOnCVSS.get()
                        || cvssV4 >= config.failBuildOnCVSS.get()
                        || useUnscored && unscoredCvss >= config.failBuildOnCVSS.get()
                        //safety net to fail on any if for some reason the above misses on 0
                        || (config.failBuildOnCVSS.get() <= 0.0f)) {
                    vulnerabilities.add(v.getName());
                }
            }
        }

        if (vulnerabilities.size() > 0) {
            final String msg = String.format("%n%nDependency-Analyze Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater than '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", config.failBuildOnCVSS.get(), vulnerabilities.join(", "))
            return CheckForFailureResult.createFailed(msg)
        } else {
            return CheckForFailureResult.createSuccess()
        }
    }

    @groovy.transform.CompileStatic
    void sendSlackNotification(CheckForFailureResult checkForFailureResult) {
        if (checkForFailureResult.failed) {
            new SlackNotificationSenderService(settings).send(getCurrentProjectName(), checkForFailureResult.msg)
        }
    }

    @groovy.transform.CompileStatic
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
    @groovy.transform.CompileStatic
    def shouldBeScanned(Project project) {
        config.scanProjects.get().isEmpty() || config.scanProjects.get().contains(project.path)
    }

    /**
     * Checks whether the given project should be skipped
     * because skipProjects contains the project's path.
     */
    @groovy.transform.CompileStatic
    def shouldBeSkipped(Project project) {
        config.skipProjects.get().contains(project.path)
    }

    /**
     * Checks whether the given configuration should be scanned
     * because either scanConfigurations is empty or it contains the
     * configuration's name.
     */
    @groovy.transform.CompileStatic
    boolean shouldBeScanned(Configuration configuration) {
        config.scanConfigurations.get().isEmpty() || config.scanConfigurations.get().contains(configuration.name)
    }

    /**
     * Checks whether the given configuration should be skipped
     * because skipConfigurations contains the configuration's name.
     */
    @groovy.transform.CompileStatic
    boolean shouldBeSkipped(Configuration configuration) {
        ((IGNORE_NON_RESOLVABLE_SCOPES_GRADLE_VERSION.compareTo(GradleVersion.current()) <= 0 && (
                "archives".equals(configuration.name) ||
                        "default".equals(configuration.name) ||
                        "runtime".equals(configuration.name) ||
                        "compile".equals(configuration.name) ||
                        "compileOnly".equals(configuration.name)))
                || config.skipConfigurations.get().contains(configuration.name))
    }

    /**
     * Checks whether the given artifact should be skipped
     * because skipGroups contains the artifact's group prefix.
     */
    @groovy.transform.CompileStatic
    def shouldBeSkipped(ResolvedArtifactResult artifact) {
        def name = artifact.id.componentIdentifier.displayName
        config.skipGroups.get().any { name.startsWith(it) }
    }

    /**
     * Checks whether the given configuration should be skipped
     * because it is a test configuration and skipTestGroups is true.
     */
    @groovy.transform.CompileStatic
    boolean shouldBeSkippedAsTest(Configuration configuration) {
        config.skipTestGroups.get() && isTestConfiguration(configuration)
    }

    /**
     * Determines if the configuration should be considered a test configuration.
     * @param configuration the configuration to insepct
     * @return true if the configuration is considered a tet configuration; otherwise false
     */
    @groovy.transform.CompileStatic
    boolean isTestConfiguration(Configuration configuration) {
        def isTestConfiguration = isTestConfigurationCheck(configuration)

        def hierarchy = configuration.hierarchy.collect({ it.name }).join(" --> ")
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
    @groovy.transform.CompileStatic
    static boolean isTestConfigurationCheck(Configuration configuration) {
        boolean isTestConfiguration = configuration.name =~ /((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/
        configuration.hierarchy.each {
            isTestConfiguration |= (it.name =~ /((^|[a-z0-9_])T|(^|_)t)est([A-Z0-9_]|$)/) as boolean
        }
        isTestConfiguration
    }

    /**
     * Determines if the onfiguration can be resolved
     * @param configuration the configuration to inspect
     * @return true if the configuration can be resolved; otherwise false
     */
    @groovy.transform.CompileStatic
    boolean canBeResolved(Configuration configuration) {
        configuration.metaClass.respondsTo(configuration, "isCanBeResolved") ?
                configuration.isCanBeResolved() : true
    }

    /**
     * Resolves the Maven POM file for a given module component.
     * Uses caching to avoid redundant network calls.
     * @param project the project context
     * @param mci the module component identifier
     * @return the resolved POM file, or null if resolution fails
     */
    @groovy.transform.CompileStatic
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
    @groovy.transform.CompileStatic
    protected void processBuildEnvironment(Project project, Engine engine) {
        project.getBuildscript().configurations.findAll { Configuration configuration ->
            shouldBeScanned(configuration) && !(shouldBeSkipped(configuration)
                    || shouldBeSkippedAsTest(configuration)) && canBeResolved(configuration)
        }.each { Configuration configuration ->
            if (CUTOVER_GRADLE_VERSION.compareTo(GradleVersion.current()) > 0) {
                processConfigLegacy configuration, engine
            } else {
                processConfigV4 project, configuration, engine, true
            }
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    @groovy.transform.CompileStatic
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
        if (config.scanSet == null) {
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
            config.scanSet.each {
                File f = project.file it
                if (f.exists()) {
                    engine.scan(f, project.name)
                } else {
                    logger.warn("ScanSet file `${f}` does not exist in ${project.name}")
                }
            }
        }

        config.additionalCpes.each {
            var dependency = new Dependency(true);
            dependency.setDescription(it.description.getOrNull())
            dependency.setDisplayFileName(it.cpe.getOrNull());
            dependency.setSha1sum(Checksum.getSHA1Checksum(it.cpe.getOrNull()));
            dependency.setSha256sum(Checksum.getSHA256Checksum(it.cpe.getOrNull()));
            dependency.setMd5sum(Checksum.getMD5Checksum(it.cpe.getOrNull()));
            dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier(CpeParser.parse(it.cpe.getOrNull()), Confidence.HIGHEST))
            dependency.setFileName("")
            dependency.setActualFilePath("")
            engine.addDependency(dependency)
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations using APIs pre-gradle 4.0.
     * @param project the project to analyze
     * @param engine the dependency-check engine
     */
    @groovy.transform.CompileStatic
    protected void processConfigLegacy(Configuration configuration, Engine engine) {
        configuration.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
            def dependencies = engine.scan(artifact.getFile())
            if (!project.gradle.startParameter.offline && dependencies != null && dependencies.size() == 1) {
                // Resolve and analyze POM for maven modules to extract additional evidence
                ModuleVersionIdentifier id = artifact.moduleVersion.getId()
                if (id.group && id.name && id.version) {
                    // Create a ModuleComponentIdentifier from the artifact's module version
                    def compId = artifact.id.componentIdentifier
                    if (compId instanceof ModuleComponentIdentifier) {
                        File pomFile = resolvePomFor(project, (ModuleComponentIdentifier) compId)
                        if (pomFile != null) {
                            try {
                                PomUtils.analyzePOM(dependencies[0], pomFile)
                            } catch (Exception e) {
                                logger.debug("Failed to analyze POM for ${id.group}:${id.name}:${id.version}: ${e.message}")
                            }
                        }
                    }
                }
            }
            addInfoToDependencies(dependencies, configuration.name,
                    artifact.moduleVersion.getId(), null)
        }
    }

    @groovy.transform.CompileStatic
    private Map<PackageURL, Set<IncludedByReference>> buildIncludedByMap(Project project, Configuration configuration, boolean scanningBuildEnv) {
        Map<PackageURL, Set<IncludedByReference>> includedByMap = new HashMap<>()
        String type = null
        if (scanningBuildEnv) {
            type = 'buildEnv'
        }
        IncludedByReference parent = new IncludedByReference(convertIdentifier(project).toString(), type)
        configuration.incoming.resolutionResult.root.getDependencies().forEach({
            if (it instanceof ResolvedDependencyResult) {
                ResolvedDependencyResult dr = (ResolvedDependencyResult) it
                ResolvedComponentResult current = dr.selected
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
        });
        return includedByMap
    }

    @groovy.transform.CompileStatic
    private static void collectDependencyMap(Map<PackageURL, Set<IncludedByReference>> includedByMap, IncludedByReference root, Set<? extends DependencyResult> dependencies, int depth) {
        for (DependencyResult it : dependencies) {
            if (it instanceof ResolvedDependencyResult) {
                ResolvedDependencyResult rdr = (ResolvedDependencyResult) it
                ResolvedComponentResult current = rdr.selected
                PackageURL purl = convertIdentifier(current)
                if (includedByMap.containsKey(purl)) {
                    // jackson-bom ends up creating an infinite loop so check if we've been here before
                    // https://github.com/dependency-check/dependency-check-gradle/issues/307
                    Set<IncludedByReference> includedBy = includedByMap.get(purl)
                    if (includedBy.contains(root)) {
                        continue;
                    }
                    includedBy.add(root)
                } else {
                    Set<IncludedByReference> rootParent = new HashSet<>()
                    rootParent.add(root)
                    includedByMap.put(purl, rootParent);
                }
                if (current.getDependencies() != null && !current.getDependencies().isEmpty() && depth < 500) {
                    collectDependencyMap(includedByMap, root, current.getDependencies(), depth + 1)
                }
            }
        }
    }

    /**
     * Process the incoming artifacts for the given project's configurations using APIs introduced in gradle 4.0+.
     * @param project the project to analyze
     * @param configuration a particular configuration of the project to analyze
     * @param engine the dependency-check engine
     * @param scanningBuildEnv true if scanning the build environment; otherwise false
     */
    protected void processConfigV4(Project project, Configuration configuration, Engine engine, boolean scanningBuildEnv = false) {
        String projectName = project.name
        String scope = "$projectName:$configuration.name"
        if (scanningBuildEnv) {
            scope += " (buildEnv)"
        }
        logger.info "- Analyzing ${scope}"

        Map<String, ModuleVersionIdentifier> componentVersions = [:]
        configuration.incoming.resolutionResult.allDependencies.each {
            if (it.hasProperty('selected')) {
                componentVersions.put(it.selected.id.toString(), it.selected.moduleVersion)
            } else if (it.hasProperty('attempted')) {
                logger.debug("Unable to resolve artifact in ${it.attempted.displayName}")
            } else {
                logger.warn("Unable to resolve: ${it}")
            }
        }
        Map<PackageURL, Set<IncludedByReference>> includedByMap = buildIncludedByMap(project, configuration, scanningBuildEnv)

        def types = config.analyzedTypes.get()
        for (String type : types) {
            List<ResolvedArtifactResult> rar = configuration.incoming.artifactView {
                lenient true
                attributes {
                    it.attribute(artifactType, type)
                }
            }.getArtifacts().toList();

            for (ResolvedArtifactResult resolvedArtifactResult : rar) {
                if (shouldBeSkipped(resolvedArtifactResult)) {
                    continue;
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
                            File pomFile = resolvePomFor(project, (ModuleComponentIdentifier) compId)
                            if (pomFile != null) {
                                try {
                                    PomUtils.analyzePOM(deps[0], pomFile)
                                } catch (Exception e) {
                                    logger.debug("Failed to analyze POM for ${compId.group}:${compId.name}:${compId.version}: ${t.message}")
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
    @groovy.transform.CompileStatic
    protected void addInfoToDependencies(List<Dependency> deps, String configurationName,
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

    @groovy.transform.CompileStatic
    private static PackageURL convertIdentifier(Project project) {
        final PackageURL p
        if (project.group) {
            p = new PackageURL("maven", project.group.toString(),
                    project.name, project.version.toString(), null, null)
        } else {
            p = PackageURLBuilder.aPackageURL().withType("gradle")
                    .withName(project.name).withVersion(project.version.toString()).build()
        }
        return p;
    }

    @groovy.transform.CompileStatic
    private static PackageURL convertIdentifier(ResolvedComponentResult result) {
        ModuleVersionIdentifier id = result.getModuleVersion()
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
        return p;
    }

    @groovy.transform.CompileStatic
    private static PackageURL convertIdentifier(ModuleComponentIdentifier id) {
        final PackageURL p = new PackageURL("maven", id.moduleIdentifier.group,
                id.moduleIdentifier.name, id.version, null, null);
        return p;
    }

    @groovy.transform.CompileStatic
    private static PackageURL convertIdentifier(ProjectComponentIdentifier id) {
        return PackageURLBuilder.aPackageURL().withType("gradle").withName(id.projectPath).build()
    }

    @groovy.transform.CompileStatic
    private static PackageURL convertIdentifier(ModuleVersionIdentifier id) {
        PackageURL p
        if (id.group) {
            p = new PackageURL("maven", id.group,
                    id.name, id.version, null, null);
        } else {
            PackageURLBuilder pb = PackageURLBuilder.aPackageURL().withType("gradle")
                    .withName(id.name)
            if (id.version) {
                pb.withVersion(id.version)
            }
        }
        return p;
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
    @groovy.transform.CompileStatic
    protected void addDependency(Engine engine, String projectName, String configurationName,
                                 ModuleVersionIdentifier id, String displayName, File file = null) {
        //id.group, id.name, id.version,
        String display = displayName ?: "${id.group}:${id.name}:${id.version}"
        Dependency dependency
        String sha256
        if (file == null) {
            logger.debug("Adding virtual dependency for ${display}")
            dependency = new Dependency(project.buildFile, true)
        } else {
            logger.debug("Adding dependency for ${display}")
            dependency = new Dependency(file)
        }

        if (dependency.sha1sum == null && dependency.virtual) {
            dependency.sha1sum = getSHA1Checksum("${id.group}:${id.name}:${id.version}")
            dependency.sha256sum = getSHA256Checksum("${id.group}:${id.name}:${id.version}")
            dependency.md5sum = getMD5Checksum("${id.group}:${id.name}:${id.version}")
            dependency.displayFileName = display
        }
        dependency.addEvidence(VENDOR, "build.gradle", "displayName", display, Confidence.MEDIUM)
        dependency.addEvidence(PRODUCT, "build.gradle", "displayName", display, Confidence.HIGH)
        if (dependency.packagePath == null) {
            dependency.name = id.name
            dependency.version = id.version
            dependency.packagePath = "${id.group}:${id.name}:${id.version}"
        }
        MavenArtifact mavenArtifact = new MavenArtifact(id.group, id.name, id.version)
        dependency.addAsEvidence("gradle", mavenArtifact, Confidence.HIGHEST)
        dependency.addProjectReference("${projectName}:${configurationName}")

        engine.addDependency(dependency)
    }

    /**
     * Check if the notCompatibleWithConfigurationCache method exists in the class.
     * @return true if it exists; false otherwise.
     */
    @groovy.transform.CompileStatic
    protected boolean hasNotCompatibleWithConfigurationCacheOption() {
        return metaClass.respondsTo(this, "notCompatibleWithConfigurationCache", String)
    }

    /**
     * Calls notCompatibleWithConfigurationCache method in order to avoid failures when
     * Gradle configuration cache is enabled.
     */
    @groovy.transform.CompileStatic
    protected void callIncompatibleWithConfigurationCache() {
        String methodName = "notCompatibleWithConfigurationCache"
        Object[] methodArgs = ["The gradle-versions-plugin isn't compatible with the configuration cache"]
        metaClass.invokeMethod(this, methodName, methodArgs)
    }
}

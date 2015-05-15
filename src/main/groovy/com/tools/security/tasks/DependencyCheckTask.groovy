package com.tools.security.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.tasks.TaskAction
import org.owasp.dependencycheck.Engine
import org.owasp.dependencycheck.data.nvdcve.CveDB
import org.owasp.dependencycheck.dependency.Dependency
import org.owasp.dependencycheck.reporting.ReportGenerator
import org.owasp.dependencycheck.utils.Settings

import static org.owasp.dependencycheck.utils.Settings.setString

class DependencyCheckTask extends DefaultTask {

    def currentProjectName = project.getName()

    @TaskAction
    def check() {
        initializeSettings()
        def engine = initializeEngine()

        verifyDependencies(engine)
        analyzeDependencies(engine)
        retrieveVulnerabilities(engine)
        generateReport(engine)
    }

    private Engine initializeEngine() {
        new Engine()
    }

    def initializeSettings() {
        Settings.initialize()
        overrideProxySetting()
    }

    def verifyDependencies(engine) {
        logger.lifecycle("Verifying dependencies for project ${currentProjectName}")
        getAllDependencies(project).each { engine.scan(it) }
    }

    def analyzeDependencies(Engine engine) {
        logger.lifecycle("Checking for updates and analyzing vulnerabilities for dependencies")
        engine.analyzeDependencies()
    }

    def retrieveVulnerabilities(Engine engine) {
        def vulnerabilities = engine.getDependencies().collect { Dependency dependency ->
            dependency.getVulnerabilities()
        }.flatten()

        logger.lifecycle("Found ${vulnerabilities.size()} vulnerabilities in project ${currentProjectName}")
    }

    def generateReport(Engine engine) {
        logger.lifecycle("Generating report for project ${currentProjectName}")
        def reportGenerator = new ReportGenerator(currentProjectName, engine.dependencies, engine.analyzers,
                new CveDB().databaseProperties)
        reportGenerator.generateReports("./reports/${currentProjectName}", ReportGenerator.Format.ALL)
    }

    def overrideProxySetting() {
        if (isProxySettingExist()) {
            logger.lifecycle("Using proxy ${project.dependencyCheck.proxyServer}:${project.dependencyCheck.proxyPort}")

            setString(Settings.KEYS.PROXY_SERVER, project.dependencyCheck.proxyServer)
            setString(Settings.KEYS.PROXY_PORT, "${project.dependencyCheck.proxyPort}")
            setString(Settings.KEYS.PROXY_USERNAME, project.dependencyCheck.proxyUsername)
            setString(Settings.KEYS.PROXY_PASSWORD, project.dependencyCheck.proxyPassword)
        }
    }

    def isProxySettingExist() {
        project.dependencyCheck.proxyServer != null && project.dependencyCheck.proxyPort != null
    }

    def getAllDependencies(project) {
        return project.getConfigurations().collect { Configuration configuration ->
            configuration.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
                artifact.getFile()
            }
        }.flatten();
    }
}

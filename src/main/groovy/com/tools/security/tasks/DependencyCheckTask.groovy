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

class DependencyCheckTask extends DefaultTask {

    @TaskAction
    def check() {
        Settings.initialize()
        def engine = new Engine()

        verifyDependencies(engine)
        analyzeDependencies(engine)
        retrieveVulnerabilities(engine)
        generateReport(engine)
    }

    def verifyDependencies(engine) {
        logger.lifecycle("Verifying dependencies")
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

        logger.lifecycle("Found ${vulnerabilities.size()} vulnerabilities")
    }

    def generateReport(Engine engine) {
        logger.lifecycle("Generating report")
        def reportGenerator = new ReportGenerator(project.getName(), engine.dependencies, engine.analyzers,
                new CveDB().databaseProperties)
        reportGenerator.generateReports("./reports", ReportGenerator.Format.ALL)
    }

    def getAllDependencies(project) {
        return project.getConfigurations().collect { Configuration configuration ->
            configuration.getResolvedConfiguration().getResolvedArtifacts().collect { ResolvedArtifact artifact ->
                artifact.getFile()
            }
        }.flatten();
    }
}

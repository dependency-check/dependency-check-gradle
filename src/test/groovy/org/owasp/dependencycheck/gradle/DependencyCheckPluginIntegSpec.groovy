package org.owasp.dependencycheck.gradle

import org.gradle.testkit.runner.GradleRunner
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification

import static org.gradle.testkit.runner.TaskOutcome.*

class DependencyCheckPluginIntegSpec extends Specification {

    @Rule final TemporaryFolder testProjectDir = new TemporaryFolder()
    File buildFile

    def setup() {
        buildFile = testProjectDir.newFile('build.gradle')
    }

    def "Plugin can be added"() {
        given:
        buildFile << """
            plugins {
                id 'org.owasp.dependencycheck'
            }
        """
    
        when:
        def result = GradleRunner.create()
            .withProjectDir(testProjectDir.root)
            .withArguments('tasks')
            .withPluginClasspath()
            .forwardOutput()
            .build()

        then:
        result.output.contains("$DependencyCheckPlugin.ANALYZE_TASK")
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        buildFile << """
            plugins {
                id 'org.owasp.dependencycheck'
            }
            apply plugin: 'java'
            
            sourceCompatibility = 1.5
            version = '1.0'
            
            repositories {
                mavenLocal()
                mavenCentral()
            }
            
            dependencies {
                compile group: 'commons-collections', name: 'commons-collections', version: '3.2'
            }
        """

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "task completes successfully when configuration cache is enabled in Gradle 7.4"() {
        given:
        buildFile << """
            plugins {
                id 'org.owasp.dependencycheck'
            }
            apply plugin: 'java'
            
            sourceCompatibility = 1.5
            version = '1.0'
            
            repositories {
                mavenLocal()
                mavenCentral()
            }
            
            dependencies {
                implementation group: 'commons-collections', name: 'commons-collections', version: '3.2'
            }
        """

        when:
        def result = GradleRunner.create()
                .withGradleVersion("7.4")
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK, "--configuration-cache")
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }
}

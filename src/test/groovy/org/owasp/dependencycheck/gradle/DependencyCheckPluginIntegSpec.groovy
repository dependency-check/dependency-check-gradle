package org.owasp.dependencycheck.gradle

import org.gradle.testkit.runner.GradleRunner
import spock.lang.Specification
import spock.lang.TempDir
import spock.util.io.FileSystemFixture

import static org.gradle.testkit.runner.TaskOutcome.SUCCESS

class DependencyCheckPluginIntegSpec extends Specification {

    @TempDir
    private FileSystemFixture fileSystemFixture

    def "Plugin can be added"() {
        given:
        fileSystemFixture.create {
            file("build.gradle").text = """
                    plugins {
                        id 'org.owasp.dependencycheck'
                    }
                """.stripIndent()
        }
        when:
        def result = GradleRunner.create()
                .withGradleVersion(gradle.version)
                .withProjectDir(fileSystemFixture.resolve("").toFile())
                .withArguments('tasks')
                .withPluginClasspath()
                .forwardOutput()
                .build()

        then:
        result.output.contains("$DependencyCheckPlugin.ANALYZE_TASK")

        where:
        gradle << GradleTestVersion.supportedVersionsForCurrentJvm
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        fileSystemFixture.create {
            file("build.gradle").text = """
                plugins {
                    id 'org.owasp.dependencycheck'
                }
                apply plugin: 'java'

                version = '1.0'

                repositories {
                    mavenLocal()
                    mavenCentral()
                }

                dependencies {
                    implementation group: 'commons-collections', name: 'commons-collections', version: '3.2'
                }
                dependencyCheck {
                    analyzers.ossIndex.enabled = false
                    nvd.datafeedUrl = 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                }
            """.stripIndent()
        }

        when:
        def result = GradleRunner.create()
                .withGradleVersion(gradle.version)
                .withProjectDir(fileSystemFixture.resolve("").toFile())
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS

        where:
        gradle << GradleTestVersion.supportedVersionsForCurrentJvm
    }

    def "task completes successfully when configuration cache is enabled"() {
        given:
        fileSystemFixture.create {
            file("build.gradle").text = """
                plugins {
                    id 'org.owasp.dependencycheck'
                }
                apply plugin: 'java'

                version = '1.0'

                repositories {
                    mavenLocal()
                    mavenCentral()
                }

                dependencies {
                    implementation group: 'commons-collections', name: 'commons-collections', version: '3.2'
                }
                dependencyCheck {
                    analyzers.ossIndex.enabled = false
                    nvd.datafeedUrl = 'https://dependency-check.github.io/DependencyCheck/hb_nvd/'
                }
            """.stripIndent()
        }

        when:
        def result = GradleRunner.create()
                .withGradleVersion(gradle.version)
                .withProjectDir(fileSystemFixture.dir("").toFile())
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK, "--configuration-cache")
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS

        where:
        gradle << GradleTestVersion.supportedVersionsForCurrentJvm
    }
}

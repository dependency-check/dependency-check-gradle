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
            dir("app") {
                file("build.gradle").text = """
                        plugins {
                            id 'org.owasp.dependencycheck'
                        }
                    """.stripIndent()
            }
        }
        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("app").toFile())
                .withArguments('tasks')
                .withPluginClasspath()
                .forwardOutput()
                .build()

        then:
        result.output.contains("$DependencyCheckPlugin.ANALYZE_TASK")
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        fileSystemFixture.create {
            dir("custom") {
                file("build.gradle").text = """
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
                    dependencyCheck {
                        nvd {
                            datafeedUrl = 'https://jeremylong.github.io/DependencyCheck/hb_nvd/'
                        }
                    }
                """.stripIndent()
            }
        }

        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("custom").toFile())
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
        fileSystemFixture.create {
            dir("configCache") {
                file("build.gradle").text = """
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
                    dependencyCheck {
                        nvd {
                            datafeedUrl = 'https://jeremylong.github.io/DependencyCheck/hb_nvd/'
                        }
                    }
                """.stripIndent()
            }
        }

        when:
        def result = GradleRunner.create()
                .withProjectDir(fileSystemFixture.resolve("configCache").toFile())
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK, "--configuration-cache")
                .withPluginClasspath()
                .withDebug(true)
                .forwardOutput()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }
}

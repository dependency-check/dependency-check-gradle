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

plugins {
    id("groovy")
    id("idea")
    id("eclipse")
    id("signing")
    id("project-report")
    id("build-dashboard")
    alias(libs.plugins.gradle.plugin.publish)
}

group = "org.owasp"
version = libs.versions.odc.get()

dependencies {
    implementation(localGroovy())
    implementation(gradleApi())

    api(libs.owasp.dependencyCheck.core)
    api(libs.owasp.dependencyCheck.utils)
    api(libs.openVuln.clients)
    api(libs.slack.webhook)

    testImplementation(gradleTestKit())
    testImplementation(libs.spock.core) {
        exclude(module = "groovy-all")
    }
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testRuntimeOnly(libs.junit.jupiter.engine)
}
tasks.test {
    useJUnitPlatform()
}
tasks.test.get().onlyIf { !project.hasProperty("skipTests") }

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

publishing {
    publications {
        val pluginPublication by registering(MavenPublication::class) {
            groupId = project.group as String
            artifactId = "dependency-check-gradle"
            version = project.version as String
            from(components["java"])
            pom {
                name.set("dependency-check-gradle")
                description.set("OWASP dependency-check gradle plugin is a software composition analysis tool used to find known vulnerable dependencies.")

                url.set("https://dependency-check.github.io/DependencyCheck/")

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://github.com/dependency-check/dependency-check-gradle/blob/main/LICENSE.txt")
                    }
                }
                developers {
                    developer {
                        id.set("jlong")
                        name.set("Jeremy Long")
                        email.set("jeremy.long@owasp.org")
                    }
                }
                scm {
                    url.set("https://github.com/dependency-check/dependency-check-gradle")
                    connection.set("scm:git:https://github.com/dependency-check/dependency-check-gradle.git")
                    developerConnection.set("scm:git:https://github.com/dependency-check/dependency-check-gradle.git")
                }
            }
        }
    }
}

gradlePlugin {
    website.set("http://dependency-check.github.io/DependencyCheck/dependency-check-gradle/index.html")
    vcsUrl.set("https://github.com/dependency-check/dependency-check-gradle/")

    plugins {
        val dependencyCheck by registering {
            id = "org.owasp.dependencycheck"
            displayName = "OWASP dependency-check-gradle plugin"
            description = "A software composition analysis plugin that identifies known vulnerable dependencies used by the project."
            tags.addAll("OWASP", "dependency-check", "gradle-plugin", "software-composition-analysis", "vulnerability-detection", "security")
            implementationClass = "org.owasp.dependencycheck.gradle.DependencyCheckPlugin"
        }
    }
}

tasks.publish.get().dependsOn(tasks.publishPlugins)

defaultTasks.add("build")

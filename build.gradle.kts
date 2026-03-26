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

val targetJavaVersion = 11
val gradleJavaVersion = JavaLanguageVersion.of(17)
val testToolchainVersion = providers.gradleProperty("testToolchainVersion")
    .map(JavaLanguageVersion::of)
    .orElse(gradleJavaVersion)

logger.lifecycle("Build targets $targetJavaVersion using JDK $gradleJavaVersion (test with JDK ${testToolchainVersion.get()})")

tasks.withType<JavaCompile>().configureEach {
    options.release.set(targetJavaVersion)
}
tasks.withType<GroovyCompile>().configureEach {
    // Groovy compiler does not support -release flags and ignores it
    // see https://github.com/gradle/gradle/issues/15703 and https://issues.apache.org/jira/browse/GROOVY-11105
    sourceCompatibility = targetJavaVersion.toString()
    targetCompatibility = targetJavaVersion.toString()
    options.release.set(targetJavaVersion)
}

dependencies {
    implementation(localGroovy())
    implementation(gradleApi())

    api(libs.owasp.dependencyCheck.core)
    api(libs.owasp.dependencyCheck.utils)
    api(libs.slack.webhook)

    testImplementation(gradleTestKit())
    testImplementation(libs.spock.core) {
        exclude(module = "groovy-all")
    }
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    onlyIf { !project.hasProperty("skipTests") }

    javaLauncher.set(
        javaToolchains.launcherFor {
            languageVersion.set(testToolchainVersion)
        }
    )
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

publishing {
    // customise POM metadata for both the main plugin and the marker artifact based on the basic Gradle plugin metadata
    publications.withType<MavenPublication>().configureEach {
        val plugin = gradlePlugin.plugins.named("dependencyCheck").get()
        pom {
            name.set(plugin.displayName)
            description.set(plugin.description)
            url.set(gradlePlugin.website)

            licenses {
                license {
                    name.set("The Apache License, Version 2.0")
                    url.set("${gradlePlugin.vcsUrl.get()}/blob/main/LICENSE.txt")
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
                url.set(gradlePlugin.vcsUrl.get())
                connection.set("scm:git:${gradlePlugin.vcsUrl.get()}.git")
                developerConnection.set("scm:git:${gradlePlugin.vcsUrl.get()}.git")
            }
        }
    }
}

signing {
    isRequired = !gradle.startParameter.taskNames.contains("publishToMavenLocal")
}

gradlePlugin {
    website.set("https://dependency-check.github.io/DependencyCheck/dependency-check-gradle")
    vcsUrl.set("https://github.com/dependency-check/dependency-check-gradle")

    plugins {
        register("dependencyCheck") {
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

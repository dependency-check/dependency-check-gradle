package org.owasp.dependencycheck.gradle

import org.gradle.api.JavaVersion
import spock.util.environment.Jvm

class GradleTestVersion {
    /**
     * The versions of Gradle supported by the plugin which should be tested against, alongside their supported
     * Java versions.
     *
     * See https://endoflife.date/gradle and/or https://docs.gradle.org/current/userguide/compatibility.html
     */
    final static def supportedVersions = [
            new GradleTestVersion(version: '7.6.6',  minJdk: 8,  maxJdk: 19),
            new GradleTestVersion(version: '8.14.4', minJdk: 8,  maxJdk: 24),
            new GradleTestVersion(version: '9.5.0',  minJdk: 17, maxJdk: 26),
    ]

    final static def supportedVersionsForCurrentJvm =
            supportedVersions.findAll { it.isSupportedOnCurrentJvm() }

    static def supportedVersionsForCurrentJvmFrom(int majorVersion) {
        supportedVersionsForCurrentJvm.findAll { it.isAtLeast(majorVersion) }
    }

    String version
    int minJdk
    int maxJdk

    def isSupportedOnCurrentJvm() {
        (minJdk..maxJdk).contains(JavaVersion.toVersion(Jvm.current.javaSpecificationVersion).majorVersion.toInteger())
    }

    def isAtLeast(int majorVersion) {
        version.split("\\.").first().toInteger() >= majorVersion
    }

    @Override
    String toString() {
        version
    }
}

package org.owasp.dependencycheck.gradle

import nebula.test.IntegrationSpec
import nebula.test.functional.ExecutionResult

class DependencyCheckConfigurationSelectionIntegSpec extends IntegrationSpec {

    def "test dependencies are ignored by default"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('skipTestGroups.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheck')

        then:
        true == result.success
    }

    def "test dependencies are scanned if skipTestGroups flag is false"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('noSkipTestGroups.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheck')

        then:
        false == result.success
        true == result.standardOutput.contains('CVE-2015-6420')
    }

    def "custom configurations are scanned by default"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('scanCustomConfiguration.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheck')

        then:
        false == result.success
        true == result.standardOutput.contains('CVE-2015-6420')
    }

    def "custom configurations are skipped if blacklisted"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('blacklistCustomConfiguration.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheck')

        then:
        true == result.success
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('skipCustomConfigurationViaWhitelist.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheck')

        then:
        true == result.success
    }

}

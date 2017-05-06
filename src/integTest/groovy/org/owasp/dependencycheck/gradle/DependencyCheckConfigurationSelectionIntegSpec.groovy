package org.owasp.dependencycheck.gradle

import nebula.test.IntegrationSpec
import nebula.test.functional.ExecutionResult

//todo   change this to use testKit

class DependencyCheckConfigurationSelectionIntegSpec extends IntegrationSpec {

    def "test dependencies are ignored by default"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('skipTestGroups.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheckAnalyze')

        then:
        true == result.success
    }

    def "test dependencies are scanned if skipTestGroups flag is false"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('noSkipTestGroups.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheckAnalyze')

        then:
        false == result.success
        true == result.standardOutput.contains('CVE-2015-6420')
        true == result.standardOutput.contains('CVE-2014-0114')
        true == result.standardOutput.contains('CVE-2016-3092')
        true == result.standardOutput.contains('CVE-2015-5262')
    }

    def "custom configurations are scanned by default"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('scanCustomConfiguration.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheckAnalyze')

        then:
        false == result.success
        true == result.standardOutput.contains('CVE-2015-6420')
    }

    def "custom configurations are skipped if blacklisted"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('blacklistCustomConfiguration.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheckAnalyze')

        then:
        true == result.success
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('skipCustomConfigurationViaWhitelist.gradle', 'build.gradle')

        when:
        ExecutionResult result = runTasks('dependencyCheckAnalyze')

        then:
        true == result.success
    }

}

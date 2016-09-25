package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.artifacts.Configuration
import spock.lang.Specification
import spock.lang.Unroll

class CheckSpec extends Specification {

    @Unroll
    def "Configuration '#configurationName' (extends no other configuration) is considered a test configuration"() {
        given:
        def configuration = stubConfiguration(configurationName)
        configuration.hierarchy >> []

        expect:
        Check.isTestConfigurationCheck(configuration)

        where:
        configurationName << ["test", "testApk", "androidTest", "androidTestApk"]
    }

    @Unroll
    def "Configuration '#configurationName' (extends no other configuration) is NOT considered a test configuration"() {
        given:
        def configuration = stubConfiguration(configurationName)
        configuration.hierarchy >> []

        expect:
        !Check.isTestConfigurationCheck(configuration)

        where:
        configurationName << ["teStart", "androIdTest"]
    }

    @Unroll
    def "Configuration '#configurationHierarchy' is considered a test configuration"() {
        given:
        def configurationName = configurationHierarchy.remove(0)
        def configuration = stubConfiguration(configurationName)
        configuration.hierarchy >> configurationHierarchy.collect { stubConfiguration(it) }

        expect:
        Check.isTestConfigurationCheck(configuration)

        where:
        configurationHierarchy << [
                ["teStart", "testRuntime", "testCompile"],
                ["teStart", "androIdTest", "androidTestCompile"]
        ]
    }

    @Unroll
    def "Configuration '#configurationHierarchy' is NOT considered a test configuration"() {
        given:
        def configurationName = configurationHierarchy.remove(0)
        def configuration = stubConfiguration(configurationName)
        configuration.hierarchy >> configurationHierarchy.collect { stubConfiguration(it) }

        expect:
        !Check.isTestConfigurationCheck(configuration)

        where:
        configurationHierarchy << [
                ["teStart", "test"],
                ["teStart", "androidTest"],
                ["teStart", "runtime", "compile"],
                ["teStart", "testRuntime", "testCompileFoo"],
                ["teStart", "androIdTest", "androidTestCompileFoo"]

        ]
    }


    def stubConfiguration(String configurationName) {
        def configuration = Stub(Configuration)
        configuration.name >> configurationName
        configuration
    }
}

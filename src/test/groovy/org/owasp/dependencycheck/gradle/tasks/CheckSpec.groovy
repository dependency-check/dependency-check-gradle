package org.owasp.dependencycheck.gradle.tasks

import org.gradle.api.artifacts.Configuration
import spock.lang.Specification
import spock.lang.Unroll

class CheckSpec extends Specification {

    @Unroll
    "IS considered a test Configuration: '#configurationHierarchy'"() {
        given:
        def configuration = stubConfiguration(configurationHierarchy[0])
        configuration.hierarchy >> configurationHierarchy.collect { stubConfiguration(it) }

        expect:
        Check.isTestConfigurationCheck(configuration)

        where:
        configurationHierarchy << [
                ["test"],
                ["testApk"],
                ["androidTest"],
                ["androidTestApk"],
                ["teStart", "testRuntime", "testCompile"],
                ["teStart", "androIdTest", "androidTestCompile"]
        ]
    }

    @Unroll
    "Is NOT considered a test configuration: '#configurationHierarchy'"() {
        given:
        def configuration = stubConfiguration(configurationHierarchy[0])
        configuration.hierarchy >> configurationHierarchy.collect { stubConfiguration(it) }

        expect:
        !Check.isTestConfigurationCheck(configuration)

        where:
        configurationHierarchy << [
                ["teStart"],
                ["androIdTest"],
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

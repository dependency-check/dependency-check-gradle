package org.owasp.dependencycheck.gradle

import org.gradle.testkit.runner.GradleRunner
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification
import static org.gradle.testkit.runner.TaskOutcome.*

class DependencyCheckConfigurationSelectionIntegSpec extends Specification {

    @Rule final TemporaryFolder testProjectDir = new TemporaryFolder()
    File buildFile

    def setup() {
        buildFile = testProjectDir.newFile('build.gradle')
    }

    def 'test dependencies are ignored by default'() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('skipTestGroups.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments('dependencyCheckAnalyze')
                .withPluginClasspath()
                .withDebug(true)
                .build()

        then:
        result.task(':dependencyCheckAnalyze').outcome == SUCCESS
    }

    def "test dependencies are scanned if skipTestGroups flag is false"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('noSkipTestGroups.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments('dependencyCheckAnalyze')
                .withPluginClasspath()
                .buildAndFail()

        then:
        result.task(':dependencyCheckAnalyze').outcome == FAILED
        result.output.contains('CVE-2015-6420')
        result.output.contains('CVE-2014-0114')
        result.output.contains('CVE-2016-3092')
        result.output.contains('CVE-2015-5262')
    }

    def "custom configurations are scanned by default"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('scanCustomConfiguration.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments('dependencyCheckAnalyze')
                .withPluginClasspath()
                .buildAndFail()

        then:
        result.task(':dependencyCheckAnalyze').outcome == FAILED
        result.output.contains('CVE-2015-6420')
    }

    def "custom configurations are skipped if blacklisted"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('blacklistCustomConfiguration.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments('dependencyCheckAnalyze')
                .withPluginClasspath()
                .build()

        then:
        result.task(':dependencyCheckAnalyze').outcome == SUCCESS
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('skipCustomConfigurationViaWhitelist.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments('dependencyCheckAnalyze')
                .withPluginClasspath()
                .build()

        then:
        result.task(':dependencyCheckAnalyze').outcome == SUCCESS
    }
}

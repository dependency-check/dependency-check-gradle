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
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .withDebug(true)
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "test dependencies are scanned if skipTestGroups flag is false"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('noSkipTestGroups.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .buildAndFail()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == FAILED
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
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .buildAndFail()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == FAILED
        result.output.contains('CVE-2015-6420')
    }

    def "custom configurations are skipped if blacklisted"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('blacklistCustomConfiguration.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('skipCustomConfigurationViaWhitelist.gradle').toURI())
        buildFile << resource.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.ANALYZE_TASK)
                .withPluginClasspath()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.ANALYZE_TASK").outcome == SUCCESS
    }

    def "aggregate task aggregates"() {
        given:
        def resource = new File(getClass().getClassLoader().getResource('aggregateParent.gradle').toURI())
        buildFile << resource.text
        File appDir = testProjectDir.newFolder('app')
        File app = new File(appDir,'build.gradle')
        def appBuild = new File(getClass().getClassLoader().getResource('aggregateApp.gradle').toURI())
        app << appBuild.text
        File coreDir = testProjectDir.newFolder('core')
        File core = new File(coreDir, 'build.gradle')
        def coreBuild = new File(getClass().getClassLoader().getResource('aggregateCore.gradle').toURI())
        core << coreBuild.text

        when:
        def result = GradleRunner.create()
                .withProjectDir(testProjectDir.root)
                .withArguments(DependencyCheckPlugin.AGGREGATE_TASK)
                .withPluginClasspath()
                .build()

        then:
        result.task(":$DependencyCheckPlugin.AGGREGATE_TASK").outcome == SUCCESS
        result.output.contains('CVE-2016-7051') //jackson cve from core
        result.output.contains('CVE-2015-6420') //commons cve from app
    }
}

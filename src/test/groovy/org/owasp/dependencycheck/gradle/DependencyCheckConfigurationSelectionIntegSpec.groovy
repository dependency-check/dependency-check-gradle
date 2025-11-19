package org.owasp.dependencycheck.gradle

import org.gradle.testkit.runner.BuildResult
import org.gradle.testkit.runner.GradleRunner

import spock.lang.Specification
import spock.lang.TempDir

import static org.gradle.testkit.runner.TaskOutcome.*
import static org.owasp.dependencycheck.gradle.DependencyCheckPlugin.*

class DependencyCheckConfigurationSelectionIntegSpec extends Specification {

    @TempDir
    File testProjectDir

    def 'test dependencies are ignored by default'() {
        given:
        copyBuildFileIntoProjectDir('skipTestGroups.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
    }

    def "test dependencies are scanned if skipTestGroups flag is false"() {
        given:
        copyBuildFileIntoProjectDir('noSkipTestGroups.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, false)
        //println "-----------------"
        //println result.output
        //println "-----------------"
        //String fileContents = new File(new File(testProjectDir, 'build/reports'), 'dependency-check-report.html').text
        //println fileContents

        then:
        result.task(":$ANALYZE_TASK").outcome == FAILED
        result.output.contains('CVE-2015-6420')
        result.output.contains('CVE-2014-0114')
        result.output.contains('CVE-2016-3092')
        //the nvd CVE was updated and the version used is no longer considered vulnerable
        //result.output.contains('CVE-2015-5262')
    }

    def "additional CPEs are scanned when present"() {
        given:
        copyBuildFileIntoProjectDir('scanAdditionalCpesConfiguration.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, false)

        then:
        result.task(":$ANALYZE_TASK").outcome == FAILED
        result.output.contains('CVE-2015-6420')
        result.output.contains('CVE-2016-3092')
    }

    def "custom configurations are scanned by default"() {
        given:
        copyBuildFileIntoProjectDir('scanCustomConfiguration.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, false)

        then:
        result.task(":$ANALYZE_TASK").outcome == FAILED
        result.output.contains('CVE-2015-6420')
    }

    def "custom configurations are skipped if blacklisted"() {
        given:
        copyBuildFileIntoProjectDir('blacklistCustomConfiguration.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
    }

    def "custom configurations are skipped when only scanning whitelisted configurations"() {
        given:
        copyBuildFileIntoProjectDir('skipCustomConfigurationViaWhitelist.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
    }

    def "groups are skipped if blacklisted"() {
        given:
        copyBuildFileIntoProjectDir('skipGroups.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
    }

    def "aggregate task aggregates"() {
        given:
        copyBuildFileIntoProjectDir('aggregateParent.gradle')
        copyResourceFileIntoProjectDir('aggregateSettings.gradle', 'settings.gradle')
        copyResourceFileIntoProjectDir('aggregateApp.gradle', 'app/build.gradle')
        copyResourceFileIntoProjectDir('aggregateCore.gradle', 'core/build.gradle')

        when:
        def result = executeTaskAndGetResult(AGGREGATE_TASK, true)

        then:
        result.task(":$AGGREGATE_TASK").outcome == SUCCESS
        result.output.contains('CVE-2016-7051') //jackson cve from core
        result.output.contains('CVE-2015-6420') //commons cve from app
    }

    def "suppressionFiles argument can be parsed and files are being respected"() {
        given:
        copyBuildFileIntoProjectDir('suppressionFiles.gradle')
        copyResourceFileIntoProjectDir('suppressions.xml', 'suppressions.xml')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
    }

    def "analysis fails when unused suppression rule is present"() {
        given:
        copyBuildFileIntoProjectDir('suppressionFilesFailOnUnusedRule.gradle')
        copyResourceFileIntoProjectDir('suppressions.xml', 'suppressions.xml')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, false)

        then:
        result.task(":$ANALYZE_TASK").outcome == FAILED
        result.output.contains('Suppression Rule had zero matches')
        result.output.contains('commons-collections')
    }

    def "analysis generates distinct reports when multiple tasks are used"() {
        given:
        copyBuildFileIntoProjectDir('multipleTasks.gradle')

        when:
        def result = executeTaskAndGetResult(ANALYZE_TASK, true)

        then:
        result.task(":$ANALYZE_TASK").outcome == SUCCESS
        def mainReport = new File(testProjectDir, 'build/reports/dependency-check/main/dependency-check-report.csv')
        def testReport = new File(testProjectDir, 'build/reports/dependency-check/test/dependency-check-report.csv')
        def buildReport = new File(testProjectDir, 'build/reports/dependency-check/build/dependency-check-report.csv')
        // the various reports exist
        mainReport.exists()
        testReport.exists()
        buildReport.exists()
        // and they contain only the CVEs expected for their respective configurations
        mainReport.text.contains('CVE-2015-6420') // CVE from commons-collections
        testReport.text.contains('CVE-2016-7051') // CVE from jackson
        buildReport.text.contains('CVE-2016-3092') // CVE from commons-fileupload
        !mainReport.text.contains('CVE-2016-7051') // CVE from jackson shouldn't be in main report
        !mainReport.text.contains('CVE-2016-3092') // CVE from commons-fileupload shouldn't be in main report
        !testReport.text.contains('CVE-2016-3092') // CVE from commons-fileupload shouldn't be in test report
        !buildReport.text.contains('CVE-2015-6420') // CVE from commons-collections shouldn't be in build report
        !buildReport.text.contains('CVE-2016-7051') // CVE from jackson shouldn't be in build report
    }

    private void copyBuildFileIntoProjectDir(String buildFileName) {
        copyResourceFileIntoProjectDir(buildFileName, 'build.gradle')
    }

    private void copyResourceFileIntoProjectDir(String resourceFileName, String targetFileName) {
        def resourceFileContent = new File(getClass().getClassLoader().getResource(resourceFileName).toURI()).text
        def targetDirectory = new File(testProjectDir, targetFileName).parentFile
        targetDirectory.mkdirs()
        def targetFile = new File(testProjectDir, targetFileName)
        targetFile << resourceFileContent
    }

    private BuildResult executeTaskAndGetResult(String taskName, boolean isBuildExpectedToPass) {
        def build = GradleRunner.create()
                .withProjectDir(testProjectDir)
                .withArguments(taskName,"--stacktrace")
                .forwardOutput()
                .withDebug(true)
                .withPluginClasspath()

        isBuildExpectedToPass ? build.build() : build.buildAndFail()
    }
}

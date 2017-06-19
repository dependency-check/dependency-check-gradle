package org.owasp.dependencycheck.gradle

import nebula.test.IntegrationSpec
import nebula.test.functional.ExecutionResult

/**
 * @author Sion Williams
 */
class DependencyCheckGradlePluginIntegSpec extends IntegrationSpec {
    def "I can add the plugin to a build with no errors"() {
        setup:
        buildFile << '''
            apply plugin: 'org.owasp.dependencycheck'
        '''.stripIndent()

        when:
        ExecutionResult result = runTasksSuccessfully('tasks')

        then:
        result.standardOutput.contains(
                String.format(
                        '%s - Identifies and reports known vulnerabilities (CVEs) in project dependencies.',
                        DependencyCheck.CHECK_TASK
                )
        )
    }

    def "I can override outputDir with extension"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('outputDir.gradle', 'build.gradle')

        when:
        runTasksSuccessfully(DependencyCheck.CHECK_TASK)

        then:
        fileExists('build/dependency-reports/dependency-check-report.html')
    }
}

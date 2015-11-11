package com.tools.security.plugin

import nebula.test.IntegrationSpec
import nebula.test.functional.ExecutionResult

/**
 * @author Sion Williams
 */
class DependencyCheckGradlePluginIntegSpec extends IntegrationSpec {
    def "I can add the plugin to a build with no errors"() {
        setup:
        buildFile << '''
            apply plugin: 'dependencyCheck'
        '''.stripIndent()

        when:
        ExecutionResult result = runTasksSuccessfully('tasks')

        then:
        result.standardOutput.contains('dependencyCheck - Produce dependency security report.')
    }

    def "I can override outputDir with extension"() {
        setup:
        writeHelloWorld('com.example')
        copyResources('outputDir.gradle', 'build.gradle')

        when:
        runTasksSuccessfully('dependencyCheck')

        then:
        fileExists('build/dependencyCheckReport')
    }
}

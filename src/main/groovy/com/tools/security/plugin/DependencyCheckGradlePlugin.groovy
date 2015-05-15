package com.tools.security.plugin

import com.tools.security.extension.DependencyCheckConfigurationExtension
import com.tools.security.tasks.DependencyCheckTask
import org.gradle.api.Plugin
import org.gradle.api.Project

class DependencyCheckGradlePlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        initializeConfigurations(project)
        registerTasks(project)
    }

    def initializeConfigurations(Project project) {
        project.extensions.create("dependencyCheck", DependencyCheckConfigurationExtension)
    }

    def registerTasks(Project project) {
        project.tasks.create("dependencyCheck", DependencyCheckTask)
    }
}
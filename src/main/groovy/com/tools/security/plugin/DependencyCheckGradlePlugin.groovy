package com.tools.security.plugin

import com.tools.security.tasks.DependencyCheckTask;
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class DependencyCheckGradlePlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        project.tasks.create("dependencyCheck", DependencyCheckTask)
    }
}
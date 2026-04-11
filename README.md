# Dependency-Check-Gradle

[![Gradle Plugin Portal](https://img.shields.io/gradle-plugin-portal/v/org.owasp.dependencycheck)](https://plugins.gradle.org/plugin/org.owasp.dependencycheck)
[![Build](https://github.com/dependency-check/dependency-check-gradle/actions/workflows/build.yml/badge.svg)](https://github.com/dependency-check/dependency-check-gradle/actions/workflows/build.yml)

The dependency-check gradle plugin allows projects to monitor dependent libraries for
known, published vulnerabilities.

## Compatibility

- Gradle 7.6.4 → 9.x (see [test matrix](src/test/groovy/org/owasp/dependencycheck/gradle/GradleTestVersion.groovy))
- Gradle running with Java 11+

### Mandatory upgrade to 12.1.0+

Due to NVD API compatibility changes, an upgrade is mandatory. See [#7463](https://github.com/dependency-check/DependencyCheck/issues/7463) for more information.

### Upgrading to 11.0.0+
- The dependency-check-gradle plugin now requires Java 11 or higher.
- The dependency-check-gradle plugin will no longer be published to Maven Central; it 
  will continue to be published to the Gradle plugin portal.

## Usage

Below are the quick start instructions. Please see the [documentation site](http://dependency-check.github.io/DependencyCheck/dependency-check-gradle/index.html)
for more detailed information on configuration and usage.

### Step 1, Apply dependency check gradle plugin

Add the plugin to your build.gradle file:

```groovy
plugins {
  id "org.owasp.dependencycheck" version "12.2.0"
}
```

### Step 2, Run gradle task

Once gradle plugin applied, run following gradle task to check dependencies:

```
gradle dependencyCheckAnalyze --info
```

The reports will be generated automatically under `build/reports` directory.

If your project includes multiple sub-projects, the report will be generated for each sub-project in their own `build/reports`.

### Multiple Configurations

Some projects may require multiple dependency-check configurations. This is supported by registering multiple tasks:

```groovy
plugins {
    id 'java'
    id 'org.owasp.dependencycheck' version '12.2.0'
}

tasks.register('dependencyCheckRelease', org.owasp.dependencycheck.gradle.tasks.Analyze) {
    dependencyCheck {
        failBuildOnCVSS = 9.0
    }
}

tasks.register('dependencyCheckCI', org.owasp.dependencycheck.gradle.tasks.Analyze) {
    dependencyCheck {
        failBuildOnCVSS = 3.0
    }
}
```

### Gradle Build Environment conflicts

Sometimes users may encounter issues with `NoSuchMethodError` exceptions due to dependency resolution conflicts with
other plugins. If you encounter this issue you will need to use `buildSrc` to pin some of the transitive dependencies of dependency-check
to specific versions compatible with all plugins in your build.

For example in `buildSrc/build.gradle`
```groovy
dependencies {
    constraints {
        // org.owasp.dependencycheck needs at least this version of jackson. Other plugins pull in older versions..
        add("implementation", "com.fasterxml.jackson:jackson-bom:2.21.2")
        // org.owasp.dependencycheck needs these versions. Other plugins pull in older versions..
        add("implementation", "org.apache.commons:commons-lang3:3.20.0")
        add("implementation", "org.apache.commons:commons-text:1.15.0")
    }
}
```

## FAQ

> **Questions List:**
> - What if my project includes multiple sub-project? How can I use this plugin for each of them including the root project?
> - How to customize the report directory?

### What if my project includes multiple sub-project? How can I use this plugin for each of them including the root project?

#### For non-aggregate scans

Try put 'apply plugin: "dependency-check"' inside the 'allprojects' or 'subprojects' if you'd like to check all sub-projects only, see below:

(1) For all projects including root project:

```groovy
buildscript {
  repositories {
    maven {
      url "https://plugins.gradle.org/m2/"
    }
  }
  dependencies {
    classpath "org.owasp:dependency-check-gradle:12.2.0"
  }
}

allprojects {
    apply plugin: 'org.owasp.dependencycheck'
}
```

(2) For all sub-projects:

```groovy
buildscript {
  repositories {
    maven {
      url "https://plugins.gradle.org/m2/"
    }
  }
  dependencies {
    classpath "org.owasp:dependency-check-gradle:12.2.0"
  }
}

subprojects {
    apply plugin: 'org.owasp.dependencycheck'
}
```

In this way, the dependency check will be executed for all projects (including root project) or just sub projects.

#### For aggregate scans

For aggregate scan, apply the plugin either on the root project or alternatively if you multi-project build is libraries and an application you can apply the plugin on the application.

### How to customize the report directory?

By default, all reports will be placed under `build/reports` folder, to change the default reporting folder name modify the configuration section like this:

```groovy
subprojects {
    apply plugin: 'org.owasp.dependencycheck'

    dependencyCheck {
        outputDirectory = "$buildDir/security-report"
    }
}
```

### How do I use the plugin with Gradle Kotlin DSL?

```kotlin
plugins {
    id("org.owasp.dependencycheck") version "12.2.0" apply false
}

allprojects {
    apply(plugin = "org.owasp.dependencycheck")
}

configure<org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension> {
    format = org.owasp.dependencycheck.reporting.ReportGenerator.Format.ALL.toString()
}
```

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=0218d602-986a-4fa2-a5f0-7c399019d793" />

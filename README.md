# Dependency-Check-Gradle

[![Build](https://github.com/dependency-check/dependency-check-gradle/actions/workflows/build.yml/badge.svg)](https://github.com/dependency-check/dependency-check-gradle/actions/workflows/build.yml)

The dependency-check gradle plugin allows projects to monitor dependent libraries for
known, published vulnerabilities.

## 11.0.0 Upgrade Notice
- The dependency-check-gradle plugin now requires Java 11 or higher.
- The dependency-check-gradle plugin will no longer be published to Maven Central; it 
  will continue to be published to the Gradle plugin portal.

## 9.0.0 Upgrade Notice

**Breaking Changes** are included in the 9.0.0 release. Please see the [9.0.0 Upgrade Notice](https://github.com/jeremylong/DependencyCheck#900-upgrade-notice)
on the primary dependency-check site for more information.

### Gradle Build Environment

With 9.0.0 users may encounter issues with `NoSuchMethodError` exceptions due to
dependency resolution. If you encounter this issue you will need to pin some of
the transitive dependencies of dependency-check to specific versions. For example:

/buildSrc/build.gradle
```groovy
dependencies {
    constraints {
        // org.owasp.dependencycheck needs at least this version of jackson. Other plugins pull in older versions..
        add("implementation", "com.fasterxml.jackson:jackson-bom:2.16.1")
        // org.owasp.dependencycheck needs these versions. Other plugins pull in older versions..
        add("implementation", "org.apache.commons:commons-lang3:3.14.0")
        add("implementation", "org.apache.commons:commons-text:1.11.0")
    }
}
```

## Current Release

The latest version is 12.0.2.

## Usage

Below are the quick start instructions. Please see the [documentation site](http://jeremylong.github.io/DependencyCheck/dependency-check-gradle/index.html)
for more detailed information on configuration and usage.

### Step 1, Apply dependency check gradle plugin

Add the plugin to your build.gradle file:

```groovy
plugins {
  id "org.owasp.dependencycheck" version "12.0.2"
}
```

### Step 2, Run gradle task

Once gradle plugin applied, run following gradle task to check dependencies:

```
gradle dependencyCheckAnalyze --info
```

The reports will be generated automatically under `build/reports` directory.

If your project includes multiple sub-projects, the report will be generated for each sub-project in their own `build/reports`.

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
    classpath "org.owasp:dependency-check-gradle:12.0.2"
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
    classpath "org.owasp:dependency-check-gradle:12.0.2"
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
    id("org.owasp.dependencycheck") version "12.0.2" apply false
}

allprojects {
    apply(plugin = "org.owasp.dependencycheck")
}

configure<org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension> {
    format = org.owasp.dependencycheck.reporting.ReportGenerator.Format.ALL.toString()
}
```

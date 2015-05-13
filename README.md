Dependency-Check-Gradle
=========

**Working in progress**

This is a DependencyCheck gradle plugin designed for project which use Gradle as build script.

Dependency-Check is a utility that attempts to detect publicly disclosed vulnerabilities contained within project dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

=========

## Usage

### Step 1, Apply dependency check gradle plugin

Please refer to either one of the solution

#### Solution 1，Bintray

`
apply plugin: "dependency-check"

buildscript {
    repositories {
        maven {
            url 'http://dl.bintray.com/wei/maven'
        }
        mavenCentral()
    }
    dependencies {
        classpath(
                'com.tools.security:dependency-check:0.0.1'
        )
    }
}
`

#### Solution 2，Gradle Plugin Portal

[dependency check gradle plugin on Gradle Plugin Portal](https://plugins.gradle.org/plugin/dependency.check)

**Build script snippet for new, incubating, plugin mechanism introduced in Gradle 2.1:**

`
// buildscript {
//     ...
// }

plugins {
    id "dependency.check" version "0.0.1"
}

// apply plugin: ...
`

**Build script snippet for use in all Gradle versions:**

`
buildscript {
  repositories {
    maven {
      url "https://plugins.gradle.org/m2/"
    }
  }
  dependencies {
    classpath "gradle.plugin.com.tools.security:dependency-check:0.0.1"
  }
}

apply plugin: "dependency.check"
`

#### Solution 3，Maven Central

working in progress

### Step 2, Run gradle task

Once gradle plugin applied, run following gradle task to check the dependencies:

`
gradle dependencyCheck
`

The reports will be generated automatically under `./reports` folder.

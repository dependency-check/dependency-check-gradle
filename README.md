Dependency-Check-Gradle
=========

**Working in progress**

This is a DependencyCheck gradle plugin designed for project which use Gradle as build script.

Dependency-Check is a utility that attempts to detect publicly disclosed vulnerabilities contained within project dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

=========

## What's New
Current latest version is `0.0.7`
- Implement nested configuration for proxy settings
- Bug fix: Remove duplicated configuration items

## Usage

### Step 1, Apply dependency check gradle plugin

Please refer to either one of the solution

#### Solution 1，Install from Maven Central (Recommended)

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'com.thoughtworks.tools:dependency-check:0.0.7'
    }
}
```

apply plugin: 'dependency.check'

#### Solution 2，Install from Gradle Plugin Portal

[dependency check gradle plugin on Gradle Plugin Portal](https://plugins.gradle.org/plugin/dependency.check)

**Build script snippet for new, incubating, plugin mechanism introduced in Gradle 2.1:**

```groovy
plugins {
    id "dependency.check" version "0.0.7"
}
```

**Build script snippet for use in all Gradle versions:**

```groovy
buildscript {
  repositories {
    maven {
      url "https://plugins.gradle.org/m2/"
    }
  }
  dependencies {
    classpath "gradle.plugin.com.tools.security:dependency-check:0.0.7"
  }
}

apply plugin: "dependency-check"
```

#### Solution 3，Install from Bintray

```groovy
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
                'com.tools.security:dependency-check:0.0.7'
        )
    }
}
```

### Step 2, Run gradle task

Once gradle plugin applied, run following gradle task to check the dependencies:

```
gradle dependencyCheck
```

The reports will be generated automatically under `./reports` folder.

If your project includes multiple sub-projects, the report will be generated for each sub-project in different sub-directory.

## FAQ

> **Questions List:**
> - What if I'm behind a proxy?
> - What if my project includes multiple sub-project? How can I use this plugin for each of them including the root project?
> - How to customize the report directory?

### What if I'm behind a proxy?

Maybe you have to use proxy to access internet, in this case, you could configure proxy settings for this plugin:

```groovy
dependencyCheck {
    proxy {
        server = "127.0.0.1"      // required, the server name or IP address of the proxy
        port = 3128               // required, the port number of the proxy
        
        // optional, the proxy server might require username
        // username = "username"
    
        // optional, the proxy server might require password
        // password = "password"
    }
}
```

In addition, if the proxy only allow HTTP `GET` or `POST` methods, you will find that the update process will always fail,
 the root cause is that every time you run `dependencyCheck` task, it will try to query the latest timestamp to determine whether need to perform an update action,
 and for performance reason the HTTP method it uses by default is `HEAD`, which probably is disabled or not supported by the proxy. To avoid this problem, you can simply change the HTTP method by below configuration:

```groovy
dependencyCheck {
    quickQueryTimestamp = false    // when set to false, it means use HTTP GET method to query timestamp. (default value is true)
}
```

### What if my project includes multiple sub-project? How can I use this plugin for each of them including the root project?

Try put 'apply plugin: "dependency-check"' inside the 'allprojects' or 'subprojects' if you'd like to check all sub-projects only, see below:

(1) For all projects including root project:

```groovy
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath "gradle.plugin.com.tools.security:dependency-check:0.0.7"
  }
}

allprojects {
    apply plugin: "dependency-check"
}
```

(2) For all sub-projects:

```groovy
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath "gradle.plugin.com.tools.security:dependency-check:0.0.7"
  }
}

subprojects {
    apply plugin: "dependency-check"
}
```

In this way, the dependency check will be executed for all projects (including root project) or just sub projects.

### How to customize the report directory?

By default, all reports will be placed under `./reports` folder, to change the default directory, just modify it in the configuration section like this:

```groovy
subprojects {
    apply plugin: "dependency-check"

    dependencyCheck {
        outputDirectory = "./customized-path/security-report"
    }
}
```
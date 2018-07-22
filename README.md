Dependency-Check-Gradle
=========

[![Build Status](https://travis-ci.org/jeremylong/dependency-check-gradle.svg?branch=master)](https://travis-ci.org/jeremylong/dependency-check-gradle)

The dependency-check gradle plugin allows projects to monitor dependent libraries for
known, published vulnerabilities.

## Current Release
The latest version is 
[![Maven Central](https://img.shields.io/maven-central/v/org.owasp/dependency-check-gradle.svg)](https://mvnrepository.com/artifact/org.owasp/dependency-check-gradle)

With the release of 2.1.1 the task name was changed from `dependencyCheck` to `dependencyCheckAnalyze`.

## Usage
Below are the quick start instructions. Please see the [documentation site](http://jeremylong.github.io/DependencyCheck/dependency-check-gradle/index.html)
for more detailed information on configuration and usage.

### Step 1, Apply dependency check gradle plugin

Install from Maven central repo

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.3.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
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
> - What if I'm behind a proxy?
> - What if my project includes multiple sub-project? How can I use this plugin for each of them including the root project?
> - How to customize the report directory?

### What if I'm behind a proxy?

Maybe you have to use proxy to access internet, in this case, you could configure proxy settings for this plugin (in addition
you should read the [proxy configuration](http://jeremylong.github.io/DependencyCheck/data/proxy.html) page):

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
    classpath 'org.owasp:dependency-check-gradle:3.3.0'
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
    mavenCentral()
  }
  dependencies {
    classpath 'org.owasp:dependency-check-gradle:3.3.0'
  }
}

subprojects {
    apply plugin: 'org.owasp.dependencycheck'
}
```

In this way, the dependency check will be executed for all projects (including root project) or just sub projects.

### How to customize the report directory?

By default, all reports will be placed under `build/reports` folder, to change the default reporting folder name modify the configuration section like this:

```groovy
subprojects {
    apply plugin: 'org.owasp.dependencycheck'

    dependencyCheck {
        outputDirectory = "security-report"
    }
}
```

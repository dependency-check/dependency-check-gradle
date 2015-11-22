Tasks
====================

Task                                        | Description
--------------------------------------------|-----------------------
dependencyCheck                             | Runs dependency-check against the project and generates a report.
[dependencyCheckUpdate](config-update.html) | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](config-purge.html)   | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration: dependencyCheck
====================
The following properties can be configured for the dependencyCheck task:

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11; since the CVSS scores are 0-10, by default the build will never fail. | 11
format               | The report format to be generated (HTML, XML, VULN, ALL).                                                          | HTML
reportsDirName       | The location to write the report(s). This directory will be located in the build directory.                        | reports
skipTestGroups       | When set to true (the default) all dependency groups that being with 'test' will be skipped.                       | true
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html)       | &nbsp;

$H$H$H$H Example
```groovy
dependencyCheck {
    autoUpdate=false
    cveValidForHours=1
    format=ALL
}
```

$H$H$H Proxy Configuration

Property          | Description                        | Default Value
------------------|------------------------------------|------------------
server            | The proxy server.                  | &nbsp;
port              | The proxy port.                    | &nbsp;
username          | Defines the proxy user name.       | &nbsp;
password          | Defines the proxy password.        | &nbsp;
connectionTimeout | The URL Connection Timeout.        | &nbsp;

$H$H$H$H Example
```groovy
dependencyCheck {
    proxy {
        server=some.proxy.server
        port=8989
    }
}
```

$H$H$H Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.
Note, if ANY of the cve configuration group are set - they should all be set to ensure things work as expected.

Config Group | Property          | Description                                                                                 | Default Value
-------------|-------------------|---------------------------------------------------------------------------------------------|------------------
cve          | url12Modified     | URL for the modified CVE 1.2.                                                               | https://nvd.nist.gov/download/nvdcve-Modified.xml.gz
cve          | url20Modified     | URL for the modified CVE 2.0.                                                               | https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz
cve          | url12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year.                    | https://nvd.nist.gov/download/nvdcve-%d.xml.gz
cve          | url20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;
data         | driver            | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
data         | driverPath        | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
data         | connectionString  | The connection string used to connect to the database.                                      | &nbsp;
data         | username          | The username used when connecting to the database.                                          | &nbsp;
data         | password          | The password used when connecting to the database.                                          | &nbsp;

$H$H$H$H Example
```groovy
dependencyCheck {
    data {
        directory='d:/nvd'
    }
}
```

$H$H$H Analyzer Configuration

In addition to the above, the dependencyCheck plugin can be configured to enable or disable specific
analyzers by configuring the `analyzer` section. Note, specific file type analyzers will automatically
disable themselves if no file types that they support are detected - so specifically disabling the
analyzers is likely not needed.

Property              | Description                                                               | Default Value
----------------------|---------------------------------------------------------------------------|------------------
archiveEnabled        | Sets whether the Archive Analyzer will be used.                           | true
zipExtensions         | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarEnabled            | Sets whether Jar Analyzer will be used.                                   | true
centralEnabled        | Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below). | true
nexusEnabled          | Sets whether Nexus Analyzer will be used. This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl              | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusUsesProxy        | Whether or not the defined proxy should be used when connecting to Nexus. | true
pyDistributionEnabled | Sets whether the Python Distribution Analyzer will be used.               | true
pyPackageEnabled      | Sets whether the Python Package Analyzer will be used.                    | true
rubygemsEnabled       | Sets whether the Ruby Gemspec Analyzer will be used.                      | true
opensslEnabled        | Sets whether or not the openssl Analyzer should be used.                  | true
cmakeEnabled          | Sets whether or not the CMake Analyzer should be used.                    | true
autoconfEnabled       | Sets whether or not the autoconf Analyzer should be used.                 | true
composerEnabled       | Sets whether or not the PHP Composer Lock File Analyzer should be used.   | true
nodeEnabled           | Sets whether or not the Node.js Analyzer should be used.                  | true
nuspecEnabled         | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.          | true
assemblyEnabled       | Sets whether or not the .NET Assembly Analyzer should be used.            | true
pathToMono            | The path to Mono for .NET assembly analysis on non-windows systems.       | &nbsp;

$H$H$H$H Example
```groovy
dependencyCheck {
    analyzer {
        assemblyEnabled=false
    }
}
```

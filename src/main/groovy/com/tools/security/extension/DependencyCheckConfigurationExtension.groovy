/*
 * This file is part of dependency-check-gradle.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2015 Wei Ma. All Rights Reserved.
 */

package com.tools.security.extension

class DependencyCheckConfigurationExtension {
    String proxyServer
    Integer proxyPort
    String proxyUsername = ""
    String proxyPassword = ""

    String cveUrl12Modified = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz"
    String cveUrl20Modified = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz"
    Integer cveStartYear = 2002
    String cveUrl12Base = "https://nvd.nist.gov/download/nvdcve-%d.xml.gz"
    String cveUrl20Base = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz"

    String outputDirectory = "./reports"
}

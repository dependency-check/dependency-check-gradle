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

package org.owasp.dependencycheck.gradle.extension

public class CveExtension {
    /**
     * URL for the modified CVE 1.2:
     *    https://nvd.nist.gov/download/nvdcve-Modified.xml.gz
     **/
    String url20Modified
    /**
     * URL for the modified CVE 1.2:
     *    https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz
     **/
    String url12Modified
    /**
     * URL for the modified CVE 1.2:
     *    https://nvd.nist.gov/download/nvdcve-%d.xml.gz
     **/
    String url20Base
    /**
     * Base URL for each year's CVE 2.0, the %d will be replaced with the year.
     *    https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz
     **/
    String url12Base
}

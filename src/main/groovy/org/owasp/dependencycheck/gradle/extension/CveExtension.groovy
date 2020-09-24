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

class CveExtension {
    /**
     * URL for the modified NVD CVE json data feed:
     *    https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz
     **/
    String urlModified
    /**
     * URL for the modified NVD CVE json data feed:
     *    https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz
     **/
    String urlBase

    String user

    String password
}

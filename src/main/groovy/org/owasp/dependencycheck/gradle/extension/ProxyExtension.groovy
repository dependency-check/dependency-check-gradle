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
/**
 * TODO - this should not be needed, instead rely on the configured HTTP or HTTPS proxies
 * https://docs.gradle.org/current/userguide/build_environment.html
 */
@Deprecated
@groovy.transform.CompileStatic
class ProxyExtension {
    String server
    Integer port
    String username
    String password
    List<String> nonProxyHosts = []
}

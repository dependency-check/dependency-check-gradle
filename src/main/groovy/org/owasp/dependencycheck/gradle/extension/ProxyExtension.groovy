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

import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * TODO - this should not be needed, instead rely on the configured HTTP or HTTPS proxies
 * https://docs.gradle.org/current/userguide/build_environment.html
 */
@Deprecated
@groovy.transform.CompileStatic
class ProxyExtension {

    private final Property<String> server
    private final Property<Integer> port
    private final Property<String> username
    private final Property<String> password
    private final ListProperty<String> nonProxyHosts

    @Inject
    ProxyExtension(ObjectFactory objects) {
        this.server = objects.property(String)
        this.port = objects.property(Integer)
        this.username = objects.property(String)
        this.password = objects.property(String)
        this.nonProxyHosts = objects.listProperty(String).empty()
    }

    @Input
    @Optional
    Property<String> getServer() {
        return server
    }

    void setServer(String value) {
        server.set(value)
    }

    @Input
    @Optional
    Property<Integer> getPort() {
        return port
    }

    void setPort(Integer value) {
        port.set(value)
    }

    @Input
    @Optional
    Property<String> getUsername() {
        return username
    }

    void setUsername(String value) {
        username.set(value)
    }

    @Input
    @Optional
    Property<String> getPassword() {
        return password
    }

    void setPassword(String value) {
        password.set(value)
    }

    @Input
    @Optional
    ListProperty<String> getNonProxyHosts() {
        return nonProxyHosts
    }

    void setNonProxyHosts(List<String> value) {
        nonProxyHosts.set(value)
    }
}

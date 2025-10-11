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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.Project
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional

import javax.inject.Inject

/**
 * The update data configuration extension. Any value not configured will use the dependency-check-core defaults.
 */
@groovy.transform.CompileStatic
class DataExtension {

    private final Property<String> directory
    private final Property<String> connectionString
    private final Property<String> username
    private final Property<String> password
    private final Property<String> driver
    private final Property<String> driverPath

    @Inject
    DataExtension(ObjectFactory objects, Project project) {
        this.directory = objects.property(String)
        this.directory.set("${project.gradle.gradleUserHomeDir}/dependency-check-data/11.0".toString())
        this.connectionString = objects.property(String)
        this.username = objects.property(String)
        this.password = objects.property(String)
        this.driver = objects.property(String)
        this.driverPath = objects.property(String)
    }

    /**
     * The directory to store the H2 database that contains the cache of the NVD CVE data.
     */
    @Input
    @Optional
    Property<String> getDirectory() {
        return directory
    }

    void setDirectory(String value) {
        directory.set(value)
    }

    /**
     * The connection string to the database.
     */
    @Input
    @Optional
    Property<String> getConnectionString() {
        return connectionString
    }

    void setConnectionString(String value) {
        connectionString.set(value)
    }

    /**
     * The user name to use when connecting to the database.
     */
    @Input
    @Optional
    Property<String> getUsername() {
        return username
    }

    void setUsername(String value) {
        username.set(value)
    }

    /**
     * The password to use when connecting to the database.
     */
    @Input
    @Optional
    Property<String> getPassword() {
        return password
    }

    void setPassword(String value) {
        password.set(value)
    }

    /**
     * The database driver name (e.g. org.h2.Driver).
     */
    @Input
    @Optional
    Property<String> getDriver() {
        return driver
    }

    void setDriver(String value) {
        driver.set(value)
    }

    /**
     * The path to the driver (JAR) in case it is not already in the classpath.
     */
    @Input
    @Optional
    Property<String> getDriverPath() {
        return driverPath
    }

    void setDriverPath(String value) {
        driverPath.set(value)
    }
}

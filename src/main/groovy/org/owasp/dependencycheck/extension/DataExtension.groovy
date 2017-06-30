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

package org.owasp.dependencycheck.extension

/**
 * The update data configuration extension. Any value not configured will use the dependency-check-core defaults.
 */
class DataExtension extends PurgeDataExtension {
    /**
     * The connection string to the database.
     */
    String connectionString
    /**
     * The user name to use when connecting to the database.
     */
    String username
    /**
     * The password to use when connecting to the database.
     */
    String password
    /**
     * The database driver name (e.g. org.h2.Driver).
     */
    String driver
    /**
     * The path to the driver (JAR) in case it is not already in the classpath.
     */
    String driverPath
}

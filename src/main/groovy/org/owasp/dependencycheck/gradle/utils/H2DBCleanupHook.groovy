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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */

package org.owasp.dependencycheck.gradle.utils

import org.gradle.process.internal.shutdown.ShutdownHookActionRegister
import org.owasp.dependencycheck.utils.H2DBLock

class H2DBCleanupHook extends org.owasp.dependencycheck.utils.H2DBCleanupHook {

    /**
     * A reference to the lock file.
     */
    def lock

    @Override
    void add(H2DBLock h2DBLock) {
        super.add(h2DBLock)
        lock = h2DBLock
        ShutdownHookActionRegister.addAction(this)
    }

    @Override
    void remove() {
        super.remove();
        ShutdownHookActionRegister.removeAction(this);
    }

    @Override
    void run() {
        if (lock != null) {
            lock.release()
            lock = null
        }
    }
}

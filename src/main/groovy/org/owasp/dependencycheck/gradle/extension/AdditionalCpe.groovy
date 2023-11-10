package org.owasp.dependencycheck.gradle.extension

import org.gradle.api.Named

/**
 * Holder for the information regarding an additional CPE to be checked.
 */
@groovy.transform.CompileStatic
class AdditionalCpe implements Named {

  AdditionalCpe(String name) {
    this.name = name;
  }

  /**
   * Name assigned to the CPE entry during configuration.
   */
  String name;

  /**
   * Description for the what the CPE represents.
   */
  String description

  /**
   * The CPE to be checked against the database.
   */
  String cpe
}

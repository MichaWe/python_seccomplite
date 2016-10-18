/*
 * All symbols that are exported into the module
 * Author: Michael Witt <m.witt@htw-berlin.de>
 * 
 */

#include <seccomp.h>
#include "inc/exported_symbols.h"

void seccomplite_export_constants(PyObject *module) {
  // Actions
  PyModule_AddIntConstant(module, "KILL", SCMP_ACT_KILL);
  PyModule_AddIntConstant(module, "TRAP", SCMP_ACT_TRAP);
  PyModule_AddIntConstant(module, "ALLOW", SCMP_ACT_ALLOW);
  
  // Comparators
  PyModule_AddIntConstant(module, "NE", SCMP_CMP_NE);
  PyModule_AddIntConstant(module, "LT", SCMP_CMP_LT);
  PyModule_AddIntConstant(module, "LE", SCMP_CMP_LE);
  PyModule_AddIntConstant(module, "EQ", SCMP_CMP_EQ);
  PyModule_AddIntConstant(module, "GE", SCMP_CMP_GE);
  PyModule_AddIntConstant(module, "GT", SCMP_CMP_GT);
  PyModule_AddIntConstant(module, "MASKED_EQ", SCMP_CMP_MASKED_EQ); 
}
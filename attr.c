/*
 * Attr submodule in seccomplite library
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

#include <Python.h>
#include <seccomp.h>
#include <stdint.h>
#include "inc/attr.h"
#include "inc/config.h"
#include "inc/seccomplite.h"

/**
 * Arch type slots definitions
 */
static PyType_Slot seccomplite_AttrTypeSlots[] = {
  { 0, NULL }
};

/**
 * Arch type specs
 */
PyType_Spec seccomplite_AttrTypeSpec = {
  MODULE_NAME "." ATTR_TYPE_NAME,
  sizeof (seccomplite_AttrObject),
  0,
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_IS_ABSTRACT,
  seccomplite_AttrTypeSlots
};

/// Attr type methods

PyTypeObject * Attr_build(void) {
  // Ready the type
  PyObject *type = PyType_FromSpec(&seccomplite_AttrTypeSpec);
  PyTypeObject *result = (PyTypeObject *) type;

  if (PyType_Ready(result) < 0) {
    return NULL;
  }

  // Assign static type properties
  PyObject_SetAttrString(type, "ACT_DEFAULT", PyLong_FromLong(SCMP_FLTATR_ACT_DEFAULT));
  PyObject_SetAttrString(type, "ACT_BADARCH", PyLong_FromLong(SCMP_FLTATR_ACT_BADARCH));
  PyObject_SetAttrString(type, "CTL_NNP", PyLong_FromLong(SCMP_FLTATR_CTL_NNP));
#ifdef SCMP_FLTATR_CTL_TSYNC
  PyObject_SetAttrString(type, "CTL_TSYNC", PyLong_FromLong(SCMP_FLTATR_CTL_TSYNC));
#endif

  return result;
}
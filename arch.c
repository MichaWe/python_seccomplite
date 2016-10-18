/*
 * Arch submodule in seccomplite library
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

#include <Python.h>
#include <seccomp.h>
#include <stdint.h>
#include "inc/arch.h"
#include "inc/seccomplite.h"

/**
 * Arch type member and methods definitions
 */
static PyMemberDef Arch_members[] = {
  {"token", T_INT, offsetof(seccomplite_ArchObject, _token), 0, "Architecture token"},
  {NULL} /* Sentinel */
};

static PyMethodDef Arch_methods[] = {
  {NULL} /* Sentinel */
};

/**
 * Arch type slots definitions
 */
static PyType_Slot seccomplite_ArchTypeSlots[] = {
  { Py_tp_methods, Arch_methods},
  { Py_tp_members, Arch_members},
  { Py_tp_init, Arch_init},
  { Py_tp_new, Arch_new},
  { Py_tp_dealloc, Arch_dealloc},
  { Py_nb_int, Arch_int},
  { 0, NULL}
};

/**
 * Arch type specs
 */
PyType_Spec seccomplite_ArchTypeSpec = {
  MODULE_NAME "." ARCH_TYPE_NAME,
  sizeof (seccomplite_ArchObject),
  0,
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  seccomplite_ArchTypeSlots
};

/// Arch type methods

void Arch_dealloc(seccomplite_ArchObject *self) {
  Py_TYPE(self)->tp_free((PyObject*) self);
}

PyObject * Arch_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  seccomplite_ArchObject *self;

  self = (seccomplite_ArchObject *) type->tp_alloc(type, 0);
  if (self != NULL) {
    self->_token = 0;
  }

  return (PyObject *) self;
}

int Arch_init(seccomplite_ArchObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"arch", NULL};

  // We accept a arch name or int
  PyObject *arch = NULL;
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &arch)) {
    return -1;
  }
  
  uint32_t arch_token = SCMP_ARCH_NATIVE;
  if (arch) {
    arch_token = PyObject_AsArchToken(arch);
  }
  
  switch (arch_token) {
    case SCMP_ARCH_NATIVE:
      self->_token = seccomp_arch_native();
      break;
    case SCMP_ARCH_X86:
    case SCMP_ARCH_X86_64:
    case SCMP_ARCH_X32:
    case SCMP_ARCH_ARM:
      self->_token = arch_token;
      break;
    case UINT32_MAX:
      self->_token = 0;
      break;
  }
  
  if (self->_token == 0) {
    PyErr_SetString(PyExc_AttributeError, "Given architecture is invalid.");
  }

  return 0;
}

PyObject * Arch_int(seccomplite_ArchObject *self) {
  return Py_BuildValue("I", self->_token);
}

PyTypeObject * Arch_build(void) {
  // Ready the type
  PyObject *type = PyType_FromSpec(&seccomplite_ArchTypeSpec);
  PyTypeObject *result = (PyTypeObject *) type;

  if (PyType_Ready(result) < 0) {
    return NULL;
  }

  // Assign static type properties
  PyObject_SetAttrString(type, "NATIVE", PyLong_FromLong(SCMP_ARCH_NATIVE));
  PyObject_SetAttrString(type, "X86", PyLong_FromLong(SCMP_ARCH_X86));
  PyObject_SetAttrString(type, "X86_64", PyLong_FromLong(SCMP_ARCH_X86_64));
  PyObject_SetAttrString(type, "X32", PyLong_FromLong(SCMP_ARCH_X32));
  PyObject_SetAttrString(type, "ARM", PyLong_FromLong(SCMP_ARCH_ARM));

  /*
  // TODO: Support later
  PyObject_SetAttrString(type, "AARCH64", PyLong_FromLong(SCMP_ARCH_AARCH64));
  PyObject_SetAttrString(type, "MIPS", PyLong_FromLong(SCMP_ARCH_MIPS));
  PyObject_SetAttrString(type, "MIPS64", PyLong_FromLong(SCMP_ARCH_MIPS64));
  PyObject_SetAttrString(type, "MIPS64N32", PyLong_FromLong(SCMP_ARCH_MIPS64N32));
  PyObject_SetAttrString(type, "MIPSEL", PyLong_FromLong(SCMP_ARCH_MIPSEL));
  PyObject_SetAttrString(type, "MIPSEL64", PyLong_FromLong(SCMP_ARCH_MIPSEL64));
  PyObject_SetAttrString(type, "MIPSEL64N32", PyLong_FromLong(SCMP_ARCH_MIPSEL64N32));
  PyObject_SetAttrString(type, "PARISC", PyLong_FromLong(SCMP_ARCH_PARISC));
  PyObject_SetAttrString(type, "PARISC64", PyLong_FromLong(SCMP_ARCH_PARISC64));
  PyObject_SetAttrString(type, "PPC", PyLong_FromLong(SCMP_ARCH_PPC));
  PyObject_SetAttrString(type, "PPC64", PyLong_FromLong(SCMP_ARCH_PPC64));
  PyObject_SetAttrString(type, "PPC64LE", PyLong_FromLong(SCMP_ARCH_PPC64LE));
  PyObject_SetAttrString(type, "S390", PyLong_FromLong(SCMP_ARCH_S390));
  PyObject_SetAttrString(type, "S390X", PyLong_FromLong(SCMP_ARCH_S390X));
   */

  return result;
}

uint32_t PyObject_AsArchToken(PyObject *o) {
  // Get the module and type of Arch type
  PyObject *seccomplite = PyState_FindModule(&SeccompLiteModule);
  PyObject *type = PyDict_GetItemString(PyModule_GetDict(seccomplite), ARCH_TYPE_NAME);
  
  // Check if this object is a number
  if (o == NULL || o == Py_None) {
    return SCMP_ARCH_NATIVE;
  }
  else if (PyLong_Check(o)) {
    uint32_t result = 0;
    PyArg_Parse(o, "I", &result);
    switch (result) {
      case SCMP_ARCH_NATIVE:
      case SCMP_ARCH_X86:
      case SCMP_ARCH_X86_64:
      case SCMP_ARCH_X32:
      case SCMP_ARCH_ARM:
        return result;
      default:
        return UINT32_MAX;
    }
  }
  else if (PyUnicode_Check(o)) {
    // Extract the string
    const char *arch_name = PyUnicode_AsString(o);
    if (strcmp(arch_name, "native") == 0) {
      return SCMP_ARCH_NATIVE;
    }
    else if (strcmp(arch_name, "x86") == 0) {
      return SCMP_ARCH_X86;
    }
    else if (strcmp(arch_name, "x86_64") == 0) {
      return SCMP_ARCH_X86_64;
    }
    else if (strcmp(arch_name, "x32") == 0) {
      return SCMP_ARCH_X32;
    }
    else if (strcmp(arch_name, "arm") == 0) {
      return SCMP_ARCH_ARM;
    }
    else {
      return UINT32_MAX;
    }
  }
  else if (PyObject_IsInstance(o, type)) {
    return ((seccomplite_ArchObject*)o)->_token;
  }
  else {
    return UINT32_MAX;
  }
}
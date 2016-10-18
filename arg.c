/*
 * Arg submodule in seccomplite library
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

#include <Python.h>
#include <seccomp.h>
#include <stdint.h>
#include "config.h"
#include "arg.h"
#include "seccomplite.h"

/**
 * Arg type member and methods definitions
 */
static PyMemberDef Arg_members[] = {
  {"arg", T_UINT, offsetof(seccomplite_ArgObject, _arg.arg), 0, "Attribute argument"},
  {"op", T_INT, offsetof(seccomplite_ArgObject, _arg.op), 0, "Attribute operation"},
  {"datum_a", T_ULONGLONG, offsetof(seccomplite_ArgObject, _arg.datum_a), 0, "Attribute first datum"},
  {"datum_b", T_ULONGLONG, offsetof(seccomplite_ArgObject, _arg.datum_b), 0, "Attribute second datum"},
  { NULL } /* Sentinel */
};

static PyMethodDef Arg_methods[] = {
  {NULL} /* Sentinel */
};

/**
 * Arch type slots definitions
 */
static PyType_Slot seccomplite_ArgTypeSlots[] = {
  { Py_tp_methods, Arg_methods },
  { Py_tp_members, Arg_members },
  { Py_tp_init, Arg_init },
  { Py_tp_new, Arg_new },
  { Py_tp_dealloc, Arg_dealloc },
  { 0, NULL }
};

/**
 * Arch type specs
 */
PyType_Spec seccomplite_ArgTypeSpec = {
  MODULE_NAME "." ARG_TYPE_NAME,
  sizeof (seccomplite_ArgObject),
  0,
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  seccomplite_ArgTypeSlots
};

/// Arg type methods

void Arg_dealloc(seccomplite_ArgObject *self) {
  Py_TYPE(self)->tp_free((PyObject*) self);
}

PyObject * Arg_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  seccomplite_ArgObject *self;

  self = (seccomplite_ArgObject *) type->tp_alloc(type, 0);
  if (self != NULL) {
    memset(&self->_arg, 0, sizeof(struct scmp_arg_cmp));
  }

  return (PyObject *) self;
}

int Arg_init(seccomplite_ArgObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"arg", "op", "datum_a", "datum_b", NULL};

  // We accept a arch name or int
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "IiK|K", kwlist, &self->_arg.arg, &self->_arg.op, &self->_arg.datum_a, &self->_arg.datum_b)) {
    return -1;
  }
  
  return 0;
}

PyTypeObject * Arg_build(void) {
  // Ready the type
  PyObject *type = PyType_FromSpec(&seccomplite_ArgTypeSpec);
  PyTypeObject *result = (PyTypeObject *) type;

  if (PyType_Ready(result) < 0) {
    return NULL;
  }
  else {
    return result;
  }
}
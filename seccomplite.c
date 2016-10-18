/*
 * Main C file for the lightweight libseccomp2 python bridge
 * Author: Michael Witt <m.witt@htw-berlin.de>
 * 
 */

#include <Python.h>
#include <seccomp.h>
#include "structmember.h"
#include "inc/config.h"
#include "inc/seccomplite.h"
#include "inc/exported_symbols.h"
#include "inc/arch.h"
#include "inc/attr.h"
#include "inc/arg.h"
#include "inc/filter.h"

/**
 * All exported methods
 */
static PyMethodDef SeccompLiteMethods[] = {
  // { "Name", function, METH_KEYWORDS or METH_VARARGS or METH_NOARGS, "description" }
  { "system_arch", (PyCFunction)seccomplite_system_arch, METH_NOARGS, "Get the native system architecture"},
  { "resolve_syscall", (PyCFunction)seccomplite_resolve_syscall, METH_KEYWORDS | METH_VARARGS, "Return the syscall number for the given syscall name"},
  { "ERRNO", (PyCFunction)seccomplite_act_errno, METH_KEYWORDS | METH_VARARGS, "Configure a seccomp action to return the specified error code"},
  { "TRACE", (PyCFunction)seccomplite_act_trace, METH_KEYWORDS | METH_VARARGS, "Configure a seccomp action to notify a tracing process with the specified value"},
  {NULL, NULL, 0, NULL} /* Closing sentinal */
};

/**
 * Main exported module definition
 */
struct PyModuleDef SeccompLiteModule = {
  PyModuleDef_HEAD_INIT,
  MODULE_NAME,
  MODULE_DESCRIPTION,
  -1,
  SeccompLiteMethods
};

/**
 * Module initializer function
 */
PyMODINIT_FUNC
PyInit_seccomplite(void) {
  // Load the module
  PyObject *seccomplite = PyModule_Create(&SeccompLiteModule);
  if (!seccomplite) {
    return NULL;
  }

  // Add all exported constants
  seccomplite_export_constants(seccomplite);

  // Ready the Arch type
  PyTypeObject *arch_type = Arch_build();
  if (!arch_type) {
    return NULL;
  }

  Py_INCREF(arch_type);
  PyModule_AddObject(seccomplite, ARCH_TYPE_NAME, (PyObject *) arch_type);
  
  // Ready the Attr type
  PyTypeObject *attr_type = Attr_build();
  if (!attr_type) {
    return NULL;
  }

  Py_INCREF(attr_type);
  PyModule_AddObject(seccomplite, ATTR_TYPE_NAME, (PyObject *) attr_type);
  
  // Ready the Arg type
  PyTypeObject *arg_type = Arg_build();
  if (!arg_type) {
    return NULL;
  }

  Py_INCREF(arg_type);
  PyModule_AddObject(seccomplite, ARG_TYPE_NAME, (PyObject *) arg_type);
  
  // Ready the Filter type
  PyTypeObject *filter_type = Filter_build();
  if (!filter_type) {
    return NULL;
  }

  Py_INCREF(filter_type);
  PyModule_AddObject(seccomplite, FILTER_TYPE_NAME, (PyObject *) filter_type);

  return seccomplite;
}

PyObject * seccomplite_system_arch(PyObject *self) {
  return Py_BuildValue("I", seccomp_arch_native());
}

PyObject * seccomplite_act_errno(PyObject *self, PyObject *args, PyObject *kwds) {
  uint32_t syscall = 0;
  static char *kwlist[] = {"code", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "I", kwlist, &syscall)) {
    return NULL;
  }
  
  return Py_BuildValue("I", SCMP_ACT_ERRNO(syscall));
}

PyObject * seccomplite_act_trace(PyObject *self, PyObject *args, PyObject *kwds) {
  uint32_t syscall = 0;
  static char *kwlist[] = {"signal", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "I", kwlist, &syscall)) {
    return NULL;
  }
  
  return Py_BuildValue("I", SCMP_ACT_TRACE(syscall));
}

PyObject * seccomplite_resolve_syscall(PyObject *self, PyObject *args, PyObject *kwds) {
  PyObject *syscall = NULL;
  PyObject *arch = NULL;
  static char *kwlist[] = {"arch", "syscall", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &arch, &syscall)) {
    return NULL;
  }

  // Arch might be a number or an architecture name
  uint32_t arch_token = PyObject_AsArchToken(arch);
  if (arch_token == UINT32_MAX) {
    PyErr_SetString(PyExc_AttributeError, "Given architecture is invalid.");
    return NULL;
  }

  // Translate native arch token if required
  if (arch_token == SCMP_ARCH_NATIVE) {
    arch_token = seccomp_arch_native();
  }

  // Try to translate the syscall
  int result = -1;
  if (PyUnicode_Check(syscall)) {
    const char *syscall_name = PyUnicode_AsString(syscall);
    result = seccomp_syscall_resolve_name_arch(arch_token, syscall_name);
  } 
  else if (PyLong_Check(syscall)) {
    // syscall number conversion not supported yet
    PyArg_Parse(syscall, "i", &result);
  }
  else {
    PyErr_SetString(PyExc_AttributeError, "Syscall must be of type unicode or int.");
    return NULL;
  }
  
  if (result == __NR_SCMP_ERROR) {
    PyErr_SetString(PyExc_AttributeError, "Syscall resolution failed.");
    return NULL;
  }
  else {
    return Py_BuildValue("i", result);
  }
}
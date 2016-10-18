/*
 * Main H file for the lightweight libseccomp2 python bridge
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

/* 
 * File:   seccomplite.h
 * Author: local
 *
 * Created on September 15, 2016, 10:42 AM
 */

#ifndef SECCOMPLITE_H
#define SECCOMPLITE_H

#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif
  /**
   * Module reference
   */
  extern struct PyModuleDef SeccompLiteModule;

  extern PyObject * seccomplite_system_arch(PyObject *self);

  extern PyObject * seccomplite_resolve_syscall(PyObject *self, PyObject *args, PyObject *kwds);
  extern PyObject * seccomplite_act_errno(PyObject *self, PyObject *args, PyObject *kwds);
  extern PyObject * seccomplite_act_trace(PyObject *self, PyObject *args, PyObject *kwds);

#ifdef __cplusplus
}
#endif

#endif /* SECCOMPLITE_H */


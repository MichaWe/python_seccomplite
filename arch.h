/*
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

/* 
 * File:   arch.h
 * Author: michael
 *
 * Created on 14. September 2016, 15:19
 */

#ifndef ARCH_H
#define ARCH_H

#include <Python.h>
#include "structmember.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * Arch type internals
   */
  typedef struct {
    PyObject_HEAD
    uint32_t _token;
  } seccomplite_ArchObject;

  /**
   * Type object builder
   * @return Set up new python type
   */
  extern PyTypeObject * Arch_build(void);

  /**
   * Object destructor
   */
  extern void Arch_dealloc(seccomplite_ArchObject *self);

  /**
   * Object allocator
   */
  extern PyObject * Arch_new(PyTypeObject *type, PyObject *args, PyObject *kwds);

  /**
   * Object initializer
   */
  extern int Arch_init(seccomplite_ArchObject *self, PyObject *args, PyObject *kwds);

  /**
   * __int__ method
   */
  extern PyObject * Arch_int(seccomplite_ArchObject *self);

  /**
   * Convert the given object into an architecture token
   * @param o Object to convert (string or number)
   * @return unsigned int or UINT32_MAX if conversion fails
   */
  extern uint32_t PyObject_AsArchToken(PyObject *o);

  /**
   * Type export
   */
  extern PyType_Spec seccomplite_ArchTypeSpec;

#ifdef __cplusplus
}
#endif

#endif /* ARCH_H */


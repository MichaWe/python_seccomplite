/* 
 * File:   arg.h
 * Author: Michael Witt <m.witt@htw-berlin.de>
 *
 * Created on 16. September 2016, 14:04
 */

#ifndef ARG_H
#define ARG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <Python.h>
#include "structmember.h"
#include <seccomp.h>
  
  /**
   * Arch type internals
   */
  typedef struct {
    PyObject_HEAD
    struct scmp_arg_cmp _arg;
  } seccomplite_ArgObject;

  /**
   * Type object builder
   * @return Set up new python type
   */
  extern PyTypeObject * Arg_build(void);

  /**
   * Object destructor
   */
  extern void Arg_dealloc(seccomplite_ArgObject *self);

  /**
   * Object allocator
   */
  extern PyObject * Arg_new(PyTypeObject *type, PyObject *args, PyObject *kwds);

  /**
   * Object initializer
   */
  extern int Arg_init(seccomplite_ArgObject *self, PyObject *args, PyObject *kwds);

  /**
   * Type export
   */
  extern PyType_Spec seccomplite_ArgTypeSpec;


#ifdef __cplusplus
}
#endif

#endif /* ARG_H */


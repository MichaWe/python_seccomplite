/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   attr.h
 * Author: michael
 *
 * Created on 16. September 2016, 13:48
 */

#ifndef ATTR_H
#define ATTR_H

#include <Python.h>
#include "structmember.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * Attr type internals
   */
  typedef struct {
    PyObject_HEAD
  } seccomplite_AttrObject;

  /**
   * Type object builder
   * @return Set up new python type
   */
  extern PyTypeObject * Attr_build(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTR_H */


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   exported_symbols.h
 * Author: michael
 *
 * Created on 14. September 2016, 14:58
 */

#ifndef EXPORTED_SYMBOLS_H
#define EXPORTED_SYMBOLS_H

#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

  void seccomplite_export_constants(PyObject *module);
  
#ifdef __cplusplus
}
#endif

#endif /* EXPORTED_SYMBOLS_H */


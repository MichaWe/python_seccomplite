/*
 * 
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

/* 
 * File:   config.h
 * Author: michael
 *
 * Created on 14. September 2016, 16:16
 */

#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MODULE_NAME
#define MODULE_NAME "seccomplite"
#endif

#ifndef MODULE_DESCRIPTION
#define MODULE_DESCRIPTION NULL
#endif
  
#ifndef ARCH_TYPE_NAME
#define ARCH_TYPE_NAME "Arch"
#endif

#ifndef ATTR_TYPE_NAME
#define ATTR_TYPE_NAME "Attr"
#endif

#ifndef ARG_TYPE_NAME
#define ARG_TYPE_NAME "Arg"
#endif
  
#ifndef FILTER_TYPE_NAME
#define FILTER_TYPE_NAME "Filter"
#endif
  
#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 3)
#define PyUnicode_AsString(o) (const char*)PyUnicode_1BYTE_DATA(o)
#else 
#define PyUnicode_AsString(o) (const char*)PyUnicode_AS_DATA(o)
#endif

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_H */


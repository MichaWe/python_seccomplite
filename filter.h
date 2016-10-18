/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   filter.h
 * Author: michael
 *
 * Created on 16. September 2016, 14:26
 */

#ifndef FILTER_H
#define FILTER_H

#include <Python.h>
#include "structmember.h"
#include <seccomp.h>  

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * Filter type internals
   */
  typedef struct {
    PyObject_HEAD
    int _def_action;
    scmp_filter_ctx _ctx;
  } seccomplite_FilterObject;

  /**
   * Type object builder
   * @return Set up new python type
   */
  extern PyTypeObject * Filter_build(void);

  /**
   * Object destructor
   */
  extern void Filter_dealloc(seccomplite_FilterObject *self);

  /**
   * Object allocator
   */
  extern PyObject * Filter_new(PyTypeObject *type, PyObject *args, PyObject *kwds);

  /**
   * Object initializer
   */
  extern int Filter_init(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Reset the given filter
   * @arguments defaction - the default filter action
   * 
   * Description:
        Resets the seccomp filter state to an initial default state, if a
        default filter action is not specified in the reset call the
        original action will be reused.  This function does not affect any
        seccomp filters alread loaded into the kernel.
   */
  extern PyObject * Filter_reset(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Merge two existing SyscallFilter objects
   * @arguments filter - a valid SyscallFilter object
   * 
   * Description:
        Merges a valid SyscallFilter object with the current SyscallFilter
        object; the passed filter object will be reset on success.  In
        order to successfully merge two seccomp filters they must have the
        same attribute values and not share any of the same architectures.
   */
  extern PyObject * Filter_merge(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);

  /**
   * Check if the seccomp filter contains a given architecture
   * @arguments arch - the architecture value, e.g. Arch.*
   * 
   * Description:
        Test to see if a given architecture is included in the filter.
        Return True is the architecture exists, False if it does not
        exist.
   */
  extern PyObject * Filter_exist_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Add an architecture to the filter.
   * @arguments arch - the architecture value, e.g. Arch.*
   * 
   * Description:
        Add the given architecture to the filter.  Any new rules added
        after this method returns successfully will be added to this new
        architecture, but any existing rules will not be added to the new
        architecture.
   */
  extern PyObject * Filter_add_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Remove an architecture from the filter.
   * @arguments arch - the architecture value, e.g. Arch.*
   * 
   * Description:
        Remove the given architecture from the filter.  The filter must
        always contain at least one architecture, so if only one
        architecture exists in the filter this method will fail.
   */
  extern PyObject * Filter_remove_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Load the filter into the Linux Kernel.
   * 
   * Description:
        Load the current filter into the Linux Kernel.  As soon as the
        method returns the filter will be active and enforcing.
   */
  extern PyObject * Filter_load(seccomplite_FilterObject *self);
  
  /**
   * Get an attribute value from the filter.
   * @arguments attr - the attribute, e.g. Attr.*
   * 
   * Description:
        Lookup the given attribute in the filter and return the
        attribute's value to the caller.
   */
  extern PyObject * Filter_get_attr(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Set a filter attribute.
   * @arguments 
        attr - the attribute, e.g. Attr.*
        value - the attribute value
   * 
   * Description:
        Lookup the given attribute in the filter and assign it the given
        value.
   */
  extern PyObject * Filter_set_attr(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Set the filter priority of a syscall.
   * @arguments
        syscall - the syscall name or number
        priority - the priority of the syscall
   * 
   * Description:
        Set the filter priority of the given syscall.  A syscall with a
        higher priority will have less overhead in the generated filter
        code which is loaded into the system.  Priority values can range
        from 0 to 255 inclusive.
   */
  extern PyObject * Filter_syscall_priority(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Add a new rule to filter.
   * @arguments
        action - the rule action: KILL, TRAP, ERRNO(), TRACE(), or ALLOW
        syscall - the syscall name or number
        args - variable number of Arg objects
   * 
   * Description:
        Add a new rule to the filter, matching on the given syscall and an
        optional list of argument comparisons.  If the rule is triggered
        the given action will be taken by the kernel.  In order for the
        rule to trigger, the syscall as well as each argument comparison
        must be true.
        In the case where the specific rule is not valid on a specific
        architecture, e.g. socket() on 32-bit x86, this method rewrites
        the rule to the best possible match.  If you don't want this fule
        rewriting to take place use add_rule_exactly().
   */
  extern PyObject * Filter_add_rule(seccomplite_FilterObject *self, PyObject *args);
  
  /**
   * Add a new rule to filter.
   * @arguments
        action - the rule action: KILL, TRAP, ERRNO(), TRACE(), or ALLOW
        syscall - the syscall name or number
        args - variable number of Arg objects
   * 
   * Description:
        Add a new rule to the filter, matching on the given syscall and an
        optional list of argument comparisons.  If the rule is triggered
        the given action will be taken by the kernel.  In order for the
        rule to trigger, the syscall as well as each argument comparison
        must be true.
        This method attempts to add the filter rule exactly as specified
        which can cause problems on certain architectures, e.g. socket()
        on 32-bit x86.  For a architecture independent version of this
        method use add_rule().
   */
  extern PyObject * Filter_add_rule_exactly(seccomplite_FilterObject *self, PyObject *args);
  
  /**
   * Export the filter in PFC format.
   * @arguments 
        file - the output file
   * 
   * Description:
        Output the filter in Pseudo Filter Code (PFC) to the given file.
        The output is functionally equivalent to the BPF based filter
        which is loaded into the Linux Kernel.
   */
  extern PyObject * Filter_export_pfc(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);
  
  /**
   * Export the filter in BPF format.
   * @argzments 
        file - the output file
   * 
   * Description:
        Output the filter in Berkley Packet Filter (BPF) to the given
        file.  The output is identical to what is loaded into the
        Linux Kernel.
   * 
   */
  extern PyObject * Filter_export_bpf(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds);

  /**
   * Extract the syscall number from the given object
   * @param object string or int holding the syscall number or name
   * @return syscall number as integer or -1 on error
   */
  extern int PyObject_AsSyscallNumber(PyObject *object);
  
  /**
   * Type export
   */
  extern PyType_Spec seccomplite_FilterTypeSpec;


#ifdef __cplusplus
}
#endif

#endif /* FILTER_H */


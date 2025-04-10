// jitremap.c - C 확장 모듈: JIT code cache에 대해 mprotect 시도

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>

static PyObject* jit_remap(PyObject* self, PyObject* args) {
    unsigned long addr;
    size_t size;
    int prot;

    if (!PyArg_ParseTuple(args, "kki", &addr, &size, &prot)) {
        return NULL;
    }

    int result = mprotect((void*)addr, size, prot);
    if (result != 0) {
        return Py_BuildValue("(i,s)", result, strerror(errno));
    }

    Py_RETURN_TRUE;
}

static PyMethodDef JitRemapMethods[] = {
    {"remap", jit_remap, METH_VARARGS, "Change memory protection of given address."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef jitremapmodule = {
    PyModuleDef_HEAD_INIT,
    "jitremap",   // name of module
    "JIT remapping module for testing mprotect.",
    -1,
    JitRemapMethods
};

PyMODINIT_FUNC PyInit_jitremap(void) {
    return PyModule_Create(&jitremapmodule);
}


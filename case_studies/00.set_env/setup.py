from setuptools import setup, Extension

setup(
    name="jitexecleak",
    version="0.1",
    ext_modules=[Extension("jitexecleak", ["jitleak.c"])],
)


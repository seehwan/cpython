from setuptools import setup, Extension

setup(
    name="jitexecleak",
    version="0.1",
    ext_modules=[Extension("jitexecleak", ["jitleak.c"])],
    include_dirs=[
        '/proj/sekvmii-PG0/mydata/cpython/build',
        '/proj/sekvmii-PG0/mydata/cpython/Include',
        '/proj/sekvmii-PG0/mydata/cpython/Include/internal'
    ],
    extra_compile_args=[],
    extra_link_args=[]
)


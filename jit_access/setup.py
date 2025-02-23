from setuptools import setup, Extension


module = Extension(
    'jitaccess',
    sources=['jitaccess.c'],
    include_dirs=[
        '/proj/sekvmii-PG0/mydata/cpython/build',
        '/proj/sekvmii-PG0/mydata/cpython/Include',
        '/proj/sekvmii-PG0/mydata/cpython/Include/internal'
    ],
    extra_compile_args=['-DPy_BUILD_CORE', '-g'],
    extra_link_args=['-g']
)

setup(
    name='jitaccess',
    version='1.0',
    description='Access CPython JIT executor buffer',
    ext_modules=[module],
)

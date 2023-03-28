from setuptools import Extension, setup
from Cython.Build import cythonize

extensions = [
    Extension("pym", ["pam_module.c", "pam.pyx"], libraries=["pam"], compiler_directives={"language_level": "3"})
]

setup(
    name="pym",
    ext_modules=cythonize(extensions),
)

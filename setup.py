from setuptools import Extension, setup
from Cython.Build import cythonize

# https://stackoverflow.com/a/75753567/3911147
extensions = [
    Extension("pam_python.pam_python", # controls in which directory the .so file will be generated
              ["pam_python/entrypoint.c", "pam_python/pam_python.pyx"], # Required files
              libraries=["pam"], # libpam
              compiler_directives={"language_level": "3"}) # Compile as Python3
]

setup(
    name="pam_python",
    ext_modules=cythonize(extensions),
)

import distutils

from Cython.Build import cythonize
from setuptools import Extension, setup


# AAARGHHH
# WHY ISNT LIBPYTHON INCLUDED BY DEFAULT???
libpython_so = distutils.sysconfig.get_config_var('INSTSONAME')
python_ldversion = distutils.sysconfig.get_config_var('LDVERSION')

# https://stackoverflow.com/a/75753567/3911147
extensions = [
    Extension("pam_python.pam_python",  # controls in which directory the .so file will be generated
              ["pam_python/entrypoint.c", "pam_python/pipe.c", "pam_python/pam_python.pyx"],  # Required files
              define_macros=[('LIBPYTHON_SO','"'+libpython_so+'"')],
              # define_macros=[('LIBPYTHON_SO','"'+libpython_so+'"'), ('CYTHON_PEP489_MULTI_PHASE_INIT', '0')],
              libraries=["pam", "python"+python_ldversion],  # libpam
              compiler_directives={"language_level": "3"})  # Compile as Python3
]

setup(
    name="pam_python",
    ext_modules=cythonize(extensions),
)

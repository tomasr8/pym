from setuptools import Extension, setup
from Cython.Build import cythonize

extensions = [
    Extension("class_test", ["class_test.pyx"], compiler_directives={"language_level": "3"})
]

setup(
    name="class_test",
    ext_modules=cythonize(extensions),
)

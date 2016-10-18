# Python Seccomp C bridge
# Although a seccomp bridge is included in libseccomp2 > 2.2 
# this serves as our own bridge that don't require Cython and
# should have a lightweight library footprint
# Author: Michael Witt <m.witt@htw-berlin.de>
# 
from distutils.core import setup, Extension

# To use a consistent encoding
from codecs import open
from os import path

pwd = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(pwd, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

# Some constants that are passed as preprocessor definitions to the 
# build chain
MODULE_NAME = 'seccomplite'
MAJOR_VERSION = '0'
MINOR_VERSION = '1'
DEVELOP_VERSION = '0a1'
MODULE_DESCRIPTION = 'lightweight libseccomp2 python bridge'

# We only export one module
seccomp_lite_module = Extension(
    module_name, 
    define_macros=[
        ('MODULE_NAME', '"{}"'.format(MODULE_NAME)),
        ('MAJOR_VERSION', '"{}"'.format(MAJOR_VERSION)),
        ('MINOR_VERSION', '"{}"'.format(MINOR_VERSION)),
        ('DEVELOP_VERSION', '"{}"'.format(DEVELOP_VERSION)),
        ('MODULE_DESCRIPTION', '"{}"'.format(MODULE_DESCRIPTION))],
    libraries=['seccomp'],
    sources=['filter.c', 'arch.c', 'attr.c', 'arg.c', 'exported_symbols.c', 'seccomplite.c'])


author = "Michael Witt"
author_email = "m.witt@htw-berlin.de"
name='PythonSeccompLite'
module_name = 'seccomplite'
major_version = 0
minor_version = 1
version = '{}.{}'.format(major_version, minor_version)
description = 'lightweight libseccomp2 python bridge'
url = 'https://github.com/seccomp/libseccomp'
source_files = ['filter.c', 'arch.c', 'attr.c', 'arg.c', 'exported_symbols.c', 'seccomplite.c']
libraries = ['seccomp']

# No more configuration beyond this line
module1 = Extension(module_name, 
  define_macros=[('MAJOR_VERSION', str(major_version)), 
    ('MINOR_VERSION', str(minor_version)), 
    ('MODULE_NAME', '"' + module_name + '"'),
    ('MODULE_DESCRIPTION', '"' + description + '"')],
  libraries=libraries,
  sources=source_files)

setup(name=name, version=version, description=description, author=author, author_email=author_email, url=url, ext_modules=[module1])

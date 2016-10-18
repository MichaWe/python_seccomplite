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
with open(path.join(pwd, 'README'), encoding='utf-8') as f:
    long_description = f.read()

# Some constants that are passed as preprocessor definitions to the 
# build chain
MODULE_NAME = 'seccomplite'
MAJOR_VERSION = '0'
MINOR_VERSION = '1'
DEVELOP_VERSION = '0a2'
MODULE_DESCRIPTION = 'lightweight libseccomp2 python bridge'

# We only export one module
seccomp_lite_module = Extension(
    MODULE_NAME, 
    define_macros=[
        ('MODULE_NAME', '"{}"'.format(MODULE_NAME)),
        ('MAJOR_VERSION', '"{}"'.format(MAJOR_VERSION)),
        ('MINOR_VERSION', '"{}"'.format(MINOR_VERSION)),
        ('DEVELOP_VERSION', '"{}"'.format(DEVELOP_VERSION)),
        ('MODULE_DESCRIPTION', '"{}"'.format(MODULE_DESCRIPTION))],
    libraries=['seccomp'],
    sources=['filter.c', 'arch.c', 'attr.c', 'arg.c', 'exported_symbols.c', 'seccomplite.c'])

setup(
    name=MODULE_NAME,

    version='{}.{}.{}'.format(MAJOR_VERSION, MINOR_VERSION, DEVELOP_VERSION),

    description=MODULE_DESCRIPTION,
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/MichaWe/python_seccomplite',

    # Author details
    author='Michael Witt',
    author_email='m.witt@htw-berlin.de',

    # Choose your license
    license='GPLv3',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Operating System Kernels :: Linux',
        'Topic :: Software Development :: Libraries :: Python Modules',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='seccomp sandbox process monitoring security',

    # Exported modules
    ext_modules=[seccomp_lite_module],

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    package_data={
    #    'sample': ['package_data.dat'],
    },

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    data_files=[], #[('my_data', ['data/data_file'])],

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    #entry_points={
    #    'console_scripts': [
    #        'sample=sample:main',
    #    ],
    #},
)
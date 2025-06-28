
from setuptools import setup, find_packages
from osv_reproducer.core.version import get_version

VERSION = get_version()

f = open('README.md', 'r')
LONG_DESCRIPTION = f.read()
f.close()

setup(
    name='osv_reproducer',
    version=VERSION,
    description='A reproducer component that can compile OSS-Fuzz projects at specific versions and run test cases',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='Eduard Pinconschi',
    author_email='eduard.pinconschi@tecnico.ulisboa.pt',
    url='https://github.com/epicosy/osv-reproducer',
    license='Apache 2.0',
    packages=find_packages(exclude=['ez_setup', 'tests*']),
    package_data={'osv_reproducer': ['templates/*']},
    include_package_data=True,
    entry_points="""
        [console_scripts]
        osv_reproducer = osv_reproducer.main:main
    """,
)

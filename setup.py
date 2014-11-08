import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='python-forensics',
    version='1.0',
    packages=['src',],
    include_package_data=True,
    license='MIT License',
    description=('A set of utilities to perform forensics on a computer system.'),
    long_description=README,
    url='https://github.com/cnobile2012/forensics',
    author='Carl J. Nobile',
    author_email='carl.nobile@gmail.com',
    classifiers=[
        'Environment :: Command Line',
        'Intended Audience :: Forensic experts, Data Recovery',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Dynamic Content',
    ],
)

from setuptools import setup, find_packages

setup(
    name='passthing',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'Click',
        'cryptography',
    ],
    entry_points='''
        [console_scripts]
        passthing=passthing.cli:cli
    ''',
)

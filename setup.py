from setuptools import setup, find_packages


setup(
    name='keymaster',
    version='0.1.0',
    description='Dead simple password store',
    author='Denys Metelskyy',
    scripts=['keymaster/keymaster.py'],
    author_email='denys.y.metelskyy@gmail.com',
    url='https://github.com/eflauzo/keymaster',
    license='MIT',
    packages=['keymaster']
)
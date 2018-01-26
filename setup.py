from setuptools import setup

setup(
    name='xadmin-plugin-guardian',
    version='1.0.0',
    include_package_data=True,
    install_requires=[
        'django-guardian'
    ],
    packages=['xplugin_guardian'],
    url='https://github.com/alexsilva/xadmin.plugin.guardian',
    license='MIT',
    author='alex',
    author_email='alex@fabricadigital.com.br',
    description='Plugin that implement the guardian support in xadmin.'
)

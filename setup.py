from setuptools import setup


setup(
    name='txKeystoneAuth',
    version='0.1.0',
    license='BSD',
    packages=['txkeystoneauth'],
    description='Keystone auth for Twiste.web',
    author='Scrapinghub',
    author_email='info@scrapinghub.com',
    url='http://github.com/scrapinghub/tx-keystone-auth',
    platforms=['Any'],
    dependency_links=[
        'git://github.com/openstack/keystonemiddleware.git#egg=keystonemiddleware',
    ],
    install_requires=['twisted', 'keystonemiddleware']
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ]
)

# create an auto rule
# to load up the auto variables inside of the main code so that larp can be
# auto configured without any change of the actual code by the intended user

from setuptools import setup

setup( name='larp',
        version='0.2',
        description='leo arp spoofer',
        url='http://github.com/p4p1/larp',
        author='p4p1',
        author_email='k0oo@icloud.com',
        license='None',
        packages=['larp'],
        scripts=['bin/larp'],
        zip_safe=False)

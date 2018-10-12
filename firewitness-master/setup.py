from setuptools import setup, find_packages
install_requires = [
    "python-iptables"
]

setup(
    name='FireWitnesss',
    version="0.1.0",
    description= 'Verify local firewalls configuration by least witness  ',
    long_description=(
        "Using least witness packet to verify a firewall passes a certain quality(packet)"
        "given a set of firewall rules"
        ),
    url='https://github.com/aceofwings/firewitness',
    author='Daniel Harrington', 'Devon Campbell', 'Nick Laufer',
    author_email='dxh7006@rit.edu', 'dmc3133@rit.edu', 'nicklaufer98@mail.rit.edu',
    license='Apache Software License 2.0',
    zip_safe=False,
    packages=find_packages(exclude=['tests*']),
    entry_points={
        'console_scripts': [
            #TODO entry path for firewitness
            #binName=Path.toModule:function
        ],
    },
    install_requires=install_requires,
)

import setuptools


with open("README.md") as file:
    long_description = file.read()

setuptools.setup(
    name="xdp-test-harness",
    version="0.1.3",
    author="Štěpán Horáček",
    author_email="shoracek@redhat.com",
    description="Test harness for testing XDP programs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shoracek/xdp-test-harness",
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Networking",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">= 3.5",
    install_requires=[
        "pyroute2",
        "scapy",
    ],
    package_data={
        "xdp_test_harness": ["bptr_probe_counter.c"],
    },
)

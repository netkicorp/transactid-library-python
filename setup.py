import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="transactid",
    version="0.1.0a1",
    author="Jeremy Kenyon",
    author_email="jeremy@netki.com",
    description="A package for working with BIP75 and BIP70 in a Python environment.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/netkicorp/transactid-library-python",
    packages=["transactid"],
    install_requires=["cryptography==2.7", "protobuf==3.9.2"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

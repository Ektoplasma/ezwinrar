import setuptools

with open("README.md", "r") as fh:

    long_description = fh.read()

setuptools.setup(

     name='ezwinrar',  

     version='1.0',

     scripts=['ezwinrar'] ,

     author="ekt0plasm",

     author_email="ekt0plasm@protonmail.com",

     description="Python tool exploiting CVE-2018-20250 found by CheckPoint folks",

     long_description=long_description,

   long_description_content_type="text/markdown",

     url="https://github.com/Ektoplasma/ezwinrar",

     packages=setuptools.find_packages(),

     classifiers=[

         "Programming Language :: Python :: 3",

         "License :: OSI Approved :: GNU GPL 3",

         "Operating System :: Windows",

     ],

 )
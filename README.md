# eszigno - Uncompress e-Szigno .es3 files from CLI

## Introduction

This is a very basic CLI tool to "uncompress" e-Szigno .es3 files and extract
the encapsulated documents from it.

See [https://e-szigno.hu|https://e-szigno.hu] for details.

**NOTE**: This tool does NOT validate digital signatures and should not be
considered secure or feature-complete in any way. It is just a quick solution
if you don't have Windows, or you cannot install the e-Szigno software.

## Usage

List files in a .es3 document:

    ./eszigno.py ls INPUT.ES3

Extract files in an .es3 document:

    ./eszigno.py extract INPUT.ES3 [-o TARGET_DIRECTORY]


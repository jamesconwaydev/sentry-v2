#!/bin/bash -eu
# The fuzz targets only import parsers that need nothing outside the
# standard library, so the package is put on the path instead of installed:
# the base image's Python is older than the 3.12 the package declares.
for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" --paths src
done

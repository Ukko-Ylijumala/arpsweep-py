#!/bin/sh

dpkg-buildpackage --no-sign -b -tc
if [ ! -d "./dist" ]; then
    mkdir -p dist
fi
mv ../arpsweep_* dist/

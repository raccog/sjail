#!/bin/bash

set -e

truncate -s 5 ./not_evil.txt

# Evil part tries to edit a file in the home directory
truncate -s 6 ~/evil.txt

#!/bin/sh

set -eu

eval path="\$$1"

exec cat "$path"/version.txt

#!/usr/bin/env bash
#
# Capture and print stdout, since gofmt doesn't use proper exit codes
#
set -e

output="$(gofmt -l -w "$@")"
[[ -z "$output" ]] && exit 0
echo "Following files were formatted, please re-add to commit"
echo $output | tr -s [:space:] '\n'

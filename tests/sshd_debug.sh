#!/usr/bin/env bash

# This script runs another instance of sshd in verbose debug mode on port 2222
# for debugging SSH connections. It does not use the system's host key.
# sudo is required so it can access system and user folders.

# change to script dir
cd "${0%/*}" || exit 1

./generate_test_keys.sh || exit 1

# NOTE the host key must be an absolute path
sudo /usr/sbin/sshd -D -e -f "$PWD/debug_sshd_config" -h "$PWD/server.ed25519" -p 2222

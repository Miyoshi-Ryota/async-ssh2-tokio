#!/bin/bash

# This script makes it easy to run the cargo tests locally without dockers
# a user "test" with password "test" is required
# It will setup all the required environment variables the authorized_keys
# By default, it will connect to the local SSH server on port 22 and use the system host key
# If "debug" is passed in as argument, it will connect to port 2222 and use unique host key (see sshd_debug.sh)

# verify sshpass is installed
if ! command -v sshpass &> /dev/null
then
    echo "sshpass not installed (sudo apt install sshpass)"
    exit 1
fi

cd "${0%/*}"

./generate_test_keys.sh || exit 1

# setup variables used by cargo test
export ASYNC_SSH2_TEST_HOST_IP="127.0.0.1"
export ASYNC_SSH2_TEST_HOST_PW="test"
export ASYNC_SSH2_TEST_HOST_USER="test"
export ASYNC_SSH2_TEST_CLIENT_PRIV="$PWD/client.ed25519"
export ASYNC_SSH2_TEST_CLIENT_PUB="$PWD/client.ed25519.pub"
export ASYNC_SSH2_TEST_CLIENT_PROT_PRIV="$PWD/client.prot.ed25519"
export ASYNC_SSH2_TEST_CLIENT_PROT_PUB="$PWD/client.prot.ed25519.pub"
export ASYNC_SSH2_TEST_CLIENT_PROT_PASS="test"
if [ "$1" == debug ] ; then
    export ASYNC_SSH2_TEST_HOST_PORT="2222"
    export ASYNC_SSH2_TEST_SERVER_PUB="$PWD/server.ed25519.pub"
else
    export ASYNC_SSH2_TEST_HOST_PORT="22"
    export ASYNC_SSH2_TEST_SERVER_PUB="/etc/ssh/ssh_host_ed25519_key.pub"
fi

# make sure client pub key is in authorized keys for test user

# use ssh-copy-id for the non-protected one since it will make all folders and files
sshpass -p "$ASYNC_SSH2_TEST_HOST_PW" ssh-copy-id -o StrictHostKeyChecking=no -p "$ASYNC_SSH2_TEST_HOST_PORT" -i "$ASYNC_SSH2_TEST_CLIENT_PRIV" "$ASYNC_SSH2_TEST_HOST_USER"@"$ASYNC_SSH2_TEST_HOST_IP" || exit 1

# manually copy the protected one since ssh-copy-id has issues with it and we are going to use the non-protected one to do it
cat $ASYNC_SSH2_TEST_CLIENT_PROT_PUB | ssh -i "$ASYNC_SSH2_TEST_CLIENT_PRIV" -p "$ASYNC_SSH2_TEST_HOST_PORT" "$ASYNC_SSH2_TEST_HOST_USER"@"$ASYNC_SSH2_TEST_HOST_IP" \
'cat - >> ~/.ssh/authorized_keys; sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys' || exit 1

cargo test -- --test-threads=2
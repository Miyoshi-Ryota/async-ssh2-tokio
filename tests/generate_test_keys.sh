#!/bin/bash

# change to script dir
cd "${0%/*}"

# generate keys if not present
[ -e "server.ed25519" ] || ssh-keygen -t ed25519 -q -f "server.ed25519" -N ""
[ -e "client.ed25519" ] || ssh-keygen -t ed25519 -q -f "client.ed25519" -N ""
[ -e "client.prot.ed25519" ] || ssh-keygen -t ed25519 -q -f "client.prot.ed25519" -N "test"

# copy files into the Dockerfile folders
cp server.ed25519 sshd-test/ssh_host_ed25519_key
cp server.ed25519.pub sshd-test/ssh_host_ed25519_key.pub
cp client.ed25519 async-ssh2-tokio/id_ed25519
cp client.ed25519.pub async-ssh2-tokio/id_ed25519.pub
cp client.prot.ed25519 async-ssh2-tokio/prot.id_ed25519
cp client.prot.ed25519.pub async-ssh2-tokio/prot.id_ed25519.pub
cp server.ed25519.pub async-ssh2-tokio

# setup authorized keys
rm -f authorized_keys
cat client.ed25519.pub >> authorized_keys
cat client.prot.ed25519.pub >> authorized_keys
mv authorized_keys sshd-test
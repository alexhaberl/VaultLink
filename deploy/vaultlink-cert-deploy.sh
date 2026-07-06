#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: vaultlink-cert-deploy.sh FULLCHAIN PRIVATE_KEY" >&2
    exit 64
fi

src_cert=$1
src_key=$2
dest=/etc/vaultlink/tls

[ -s "$src_cert" ] || { echo "certificate missing or empty" >&2; exit 1; }
[ -s "$src_key" ] || { echo "private key missing or empty" >&2; exit 1; }

install -d -o root -g vaultlink -m 0750 "$dest"
install -o root -g vaultlink -m 0640 "$src_cert" "$dest/.fullchain.pem.new"
install -o root -g vaultlink -m 0640 "$src_key" "$dest/.privkey.pem.new"
mv -f "$dest/.fullchain.pem.new" "$dest/fullchain.pem"
mv -f "$dest/.privkey.pem.new" "$dest/privkey.pem"
systemctl try-restart vaultlink.service


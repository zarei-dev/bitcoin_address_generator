#!/bin/bash

# Function to generate a random private key
generate_private_key() {
    openssl rand -hex 32
}

# Function to convert private key to WIF
private_key_to_wif() {
    local private_key=$1
    local prefix="80" # Mainnet prefix for private key
    local extended_key="${prefix}${private_key}"
    local checksum=$(echo -n "${extended_key}" | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -sha256 -binary | head -c 4 | xxd -p -c 4)
    echo "${extended_key}${checksum}" | xxd -r -p | base58
}

# Function to get public key from private key using Python
private_key_to_public_key() {
    local private_key=$1
    python3 -c "
import sys
import ecdsa

private_key = bytes.fromhex('$private_key')
sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
vk = sk.verifying_key
public_key = b'\x04' + vk.to_string()
print(public_key.hex())
"
}

# Function to get Bitcoin address from public key using Python and pycryptodome
public_key_to_address() {
    local public_key=$1
    python3 -c "
import sys
import hashlib
import base58
from Crypto.Hash import RIPEMD160

def ripemd160(x):
    h = RIPEMD160.new()
    h.update(x)
    return h.digest()

public_key = bytes.fromhex('$public_key')
sha256 = hashlib.sha256(public_key).digest()
ripemd160_hash = ripemd160(sha256)
address_bytes = b'\x00' + ripemd160_hash
checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
address = address_bytes + checksum
print(base58.b58encode(address).decode())
"
}

# Function to check and install missing Python packages
install_requirements() {
    local requirements=("ecdsa" "pycryptodome" "progressbar2")
    for package in "${requirements[@]}"; do
        if ! python3 -c "import ${package}" &> /dev/null; then
            echo "Installing ${package}..."
            pip install ${package} > /dev/null 2>&1
            echo "${package} installed."
        fi
    done
}

# Main function to find a Bitcoin address with a specific prefix
find_address_with_prefix() {
    local prefix=$1
    python3 - <<END
import sys
import ecdsa
import hashlib
import base58
from Crypto.Hash import RIPEMD160
import progressbar
import time

def ripemd160(x):
    h = RIPEMD160.new()
    h.update(x)
    return h.digest()

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160_hash = ripemd160(sha256)
    address_bytes = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    return base58.b58encode(address_bytes + checksum).decode()

def private_key_to_wif(private_key):
    prefix = '80'
    extended_key = prefix + private_key
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended_key)).digest()).digest()[:4]
    return base58.b58encode(bytes.fromhex(extended_key) + checksum).decode()

prefix = "${prefix}"
attempts = 0

bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
bar.start()

while True:
    private_key = ecdsa.util.randrange(ecdsa.SECP256k1.order).to_bytes(32, byteorder='big').hex()
    public_key = private_key_to_public_key(private_key).hex()
    address = public_key_to_address(bytes.fromhex(public_key))
    attempts += 1
    bar.update(attempts)
    if address.startswith('1' + prefix) or address.startswith('3' + prefix):
        bar.finish()
        private_key_wif = private_key_to_wif(private_key)
        print(f'\nFound address: {address}')
        print(f'Private key: {private_key}')
        print(f'Private key (WIF): {private_key_wif}')
        print(f'Public key: {public_key}')
        break
END
}

# Check if the prefix is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <prefix>"
    exit 1
fi

# Install necessary Python packages
install_requirements

# Start finding the address
find_address_with_prefix $1

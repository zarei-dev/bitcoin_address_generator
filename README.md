# Bitcoin Address Generator

This script generates a P2PKH Bitcoin address with a specified prefix. It uses `openssl` for generating private keys, and Python libraries (`ecdsa`, `pycryptodome`, `progressbar2`) for cryptographic operations and displaying a progress bar.

## Prerequisites

- `openssl` (to generate private keys)
- `base58` (to encode keys in base58 format)
- Python 3
- Python packages: `ecdsa`, `pycryptodome`, `progressbar2`

### Install `openssl` and `base58`

```bash
sudo apt-get install openssl base58
```

### Install Python Packages
The script automatically checks for and installs the required Python packages. You can also manually install them using:
```bash
pip install ecdsa pycryptodome progressbar2
```

## Usage
Clone the repository and run the script:
```bash
git clone https://github.com/zarei-dev/bitcoin_address_generator
cd bitcoin_address_generator
chmod +x generate_address.sh
./generate_address.sh <prefix>
```
Replace `<prefix>` with the desired prefix for the Bitcoin address.

## Script Explanation
1. Private Key Generation: Uses openssl to generate a random 256-bit (32-byte) private key.
1. WIF Conversion: Converts the private key to Wallet Import Format (WIF) by adding a prefix, computing a checksum, and encoding it in base58.
1. Public Key Generation: Uses Python and the ecdsa library to derive the public key from the private key.
1. Address Generation: Uses Python with pycryptodome to compute the RIPEMD-160 hash, compute the SHA-256 hash, add the network byte, compute the checksum, and encode the result in base58 to produce the Bitcoin address.
1. Prefix Matching Loop with Progress Bar: Continuously generates keys, updates the progress bar, and checks if the address starts with the specified prefix. If it finds a match, it stops the progress bar and outputs the relevant keys.
1. Package Installation: Checks if the required Python packages are installed and installs them if necessary, suppressing the verbose output to keep it clean.
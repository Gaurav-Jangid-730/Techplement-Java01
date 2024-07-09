# File_encrypt_decrypt

## Description
File_encrypt_decrypt is a Java-based command-line tool for file encryption and decryption. It supports various encryption algorithms such as AES, RSA, Blowfish, Twofish, and ChaCha20.

## Features
- Supports encryption and decryption using multiple algorithms (AES, RSA, Twofish, Blowfish, ChaCha20).
- Command-line interface for easy usage.
- Supports various key sizes for each algorithm.


## Installation
To install File_encrypt_decrypt, clone the repository and navigate to the project directory:

```bash
git clone https://github.com/Gaurav-Jangid-730/Techplement-Java01.git
cd Techplement-Java01
```

## Usage
To use File_encrypt_decrypt, execute the following command:

```bash
java -jar File_encrypter_decrypter.jar [options]
```

## Options
* `-a, --algorithm <algorithm>`: Specify the encryption algorithm to use (e.g., AES, RSA, Blowfish).
* `-m, --mode <mode>`: Specify the mode (encrypt or decrypt).
* `-i, --input <file>`: Specify the input file.
* `-o, --output <file>`: Specify the output file.
* `-k, --key <file>`: Specify the key file (use only when you decrypt).
* `-ks, --keysize <keysize>`: Specify the key size (for applicable algorithms).
* `-v, --verbose`: (Optional) Enable verbose mode for detailed output.
* `-h, --help`: Display help message.

## Supported Key Sizes in File_encrypt_decrypt
Ensure to specify the correct key size when using the `-ks` or `--keysize` option with File_encrypt_decrypt:

* AES: 128, 192, 256 bits
* RSA: Typically 1024, 2048, 3072, 4096 bits
* Twofish: 128, 192, 256 bits
* Blowfish: 32 to 448 bits (in multiples of 8 bits)
* ChaCha20: 128, 256 bits
  
## Example
* Encrypt a file using AES:

```bash
java -jar File_encrypter_decrypter.jar -a AES -m encrypt -i input.txt -o encrypted.enc -ks 128
```
* Decrypt a file using RSA:

```bash
java -jar File_encrypter_decrypter.jar -a RSA -m decrypt -i encrypted.enc -o decrypted.txt -k encrypted.enc.key
```
## Team Members

### Team Leader
- Gaurav Sharma

### Contributors
- Sunil Choudhary
- Pabitra Bera
- Rama Krishna Mattaparthi
- Kalpesh Krushnat Kumbhar

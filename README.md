# Steps to Generate RSA Key Pair for JWT

This guide outlines how to generate an RSA key pair (private and public keys) that can be used for signing and verifying JSON Web Tokens (JWTs).

**Step 1: Create the `certs` directory and generate keys**

Open your terminal and execute the following commands sequentially:

```bash
cd ..                     # Go back one level to your project's root directory
mkdir certs               # Create the certs directory
cd certs                  # Enter the certs directory

# Generate a 2048-bit private key and save it as private.pem
openssl genrsa -out private.pem 2048

# Extract the corresponding public key from private.pem and save it as public.pem
openssl rsa -in private.pem -pubout -out public.pem
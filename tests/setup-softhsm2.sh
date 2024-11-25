#!/bin/bash

# set base directory
if readlink ${BASH_SOURCE[0]} > /dev/null; then
	pp11_test_base_dir="$( dirname "$( readlink ${BASH_SOURCE[0]} )" )"
else
	pp11_test_base_dir="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

pp11_test_token_dir="$pp11_test_base_dir/tokens"
if [ -d "$pp11_test_token_dir" ]; then
    rm -rf "$pp11_test_token_dir"
fi
mkdir "$pp11_test_token_dir"

sed "s|__BASE_DIR__|$pp11_test_base_dir|g" "$pp11_test_base_dir/softhsm2.conf.in" > "$pp11_test_base_dir/softhsm2.conf"
export SOFTHSM2_CONF="$pp11_test_base_dir/softhsm2.conf"
echo "Using SOFTHSM2_CONF=$pp11_test_base_dir/softhsm2.conf"

# Check for PKCS#11 module in default paths
default_paths=(
    "/usr/local/lib/softhsm/libsofthsm2.so"
    "/usr/lib/softhsm/libsofthsm2.so"
)

PKCS11_MODULE=""
for path in "${default_paths[@]}"; do
    if [ -f "$path" ]; then
        PKCS11_MODULE="$path"
        break
    fi
done

if [ -z "$PKCS11_MODULE" ]; then
    echo "Error: PKCS#11 module not found in default paths."
    echo "Please install SoftHSM2 or specify the module path."
    exit 1
fi

export PKCS11_MODULE
echo "Using PKCS11_MODULE=$PKCS11_MODULE"

# Initialize the token
softhsm2-util --init-token --slot 0 --label "ProxyTestToken" --so-pin 1234 --pin 1234 || {
    echo "Error: Failed to initialize token."
    exit 1
}

# Generate the key pair
pkcs11-tool --module "$PKCS11_MODULE" --login --pin 1234 --keypairgen --key-type EC:prime256v1 --id 01 --label ProxyTestExistingECKey || {
    echo "Error: Failed to generate key pair."
    exit 1
}
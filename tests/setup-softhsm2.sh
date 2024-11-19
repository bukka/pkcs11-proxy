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

softhsm2-util --init-token --slot 0 --label "ProxyTestToken" --so-pin 1234 --pin 1234

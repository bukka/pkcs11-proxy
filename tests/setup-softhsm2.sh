#!/bin/bash

softhsm2-util --init-token --slot 0 --label "ProxyTestToken" --so-pin 1234 --pin 1234

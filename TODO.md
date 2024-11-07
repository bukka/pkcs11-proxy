# TODO list

## Build

- Fix all warnings
- Fix build with latest OpenSSL 
- Check that libseccomp (e.g. libseccomp-dev on Ubuntu) is available
  - it should be probably completely optional
- The mksyscall script looks a bit messy - think about better solution
- Come up with some better way of using libdl rather than including static lib to source
- Update and test debian scripts

## Proxy

- Module/Dispatcher: Support more complex mechanisms
- TLS: Support TLS 1.3
- TLS: Add cert support

## Tests and tools

- Create integration test framework
  - Presetting and clean up of SoftHSM
  - Use python-pkcs11 for PKCS#11 testing
- Move p11proxy-mitm to the tools directory
- Introduce Clan formatter and reformat code

## Docs

- Improve README
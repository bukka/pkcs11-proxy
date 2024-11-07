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

- Support more complex mechanisms

## Tests and tools

- Create integration test framework
- Move p11proxy-mitm to the tools directory
- Introduce Clan formatter and reformat code

## Docs

- Improve README
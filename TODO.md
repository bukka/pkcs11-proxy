# TODO list

## Build

- Check that libseccomp (e.g. libseccomp-dev on Ubuntu) is available
  - it should be probably completely optional
- The mksyscall script looks a bit messy - think about better solution
- Come up with some better way of using libdl rather than including static lib to source
- Update and test debian scripts

## Proxy

- Module/Dispatcher: Support more mechanisms
- TLS: Support TLS 1.3
- TLS: Add cert support

## Tests and tools

- Extend test coverage
- Introduce Clang formatter and reformat code

## Docs

- Improve README
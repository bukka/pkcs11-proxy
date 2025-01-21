# TODO list

## Build

- Check that libseccomp (e.g. libseccomp-dev on Ubuntu) is available
  - it should be probably completely optional
- The mksyscall script looks a bit messy - think about better solution
- Come up with some better way of using libdl rather than including static lib to source
- Update and test debian scripts

## Proxy

- Configurable logging with option to log to the log file and setting levels
  - there should be an option for the level - DEBUG, INFO, WARNING, ERROR
  - it should be possible to set the log file (including /dev/stderr and syslog)
  - adding time prefix
- Module/Dispatcher: Support more mechanisms
- TLS: Support TLS 1.3
- TLS: Add cert support

## Tests and tools

- Extend test coverage
- Introduce Clang formatter and reformat code

## Docs

- Improve README
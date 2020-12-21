# QPGxxxx OpenThead

This repository contains the specific files needed
to enable OpenThread on Qorvo platforms.

Example applications on the different platforms are available
in the OpenThread repository, which can be found under:

> <https://github.com/openthread/openthread>

## Description

For each platform a ftd library and a mtd library is provided.
The ftd library supports the commissioner role, the mtd library does not.

## Supported platforms

### Transceiver/Co-Processor platforms

- GP712
- QPG7015M

These chipsets are best suited to function in the ftd role,
combined with a host platform.

The libraries contain the required glue to interface with Linux based kernel drivers.

See [GP712 usage instructions](https://github.com/openthread/openthread/blob/master/examples/platforms/gp712/README.md)
to setup an OpenThread application on these platforms.

### SoC platforms

- QPG6095
- QPG6100

The libraries contain the HAL code and HW accelerated mbed support (if applicable).

## More information

For more information on our product line and support options
Please visit [www.qorvo.com](www.qorvo.com)

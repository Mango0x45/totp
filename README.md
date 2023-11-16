# totp

`totp` is a command-line utility to generate TOTP keys from the command-line.
This is very useful for integrating 2-factor authentication support into your
existing password-management setup.  `totp` supports both TOTP secret keys and
OTP URIs as input.  This means you can also integrate `totp` together with
`zbarimg` to generate TOTP codes from scannable QR codes.

## Depdendencies

`totp` depends on libssl, libcrypto, and liburiparser.  You probably already
have the first two.  If liburiparser isn’t in your systems repositories, you can
obtain it from [here][1]


## Installation

Installation is made easy with the provided Makefile:

    $ make
    $ make install

## Usage

The `totp` utility reads TOTP secret keys from the standard input and prints the
corresponding codes to the standard output.  You can use multiple keys:

    $ printf '7KFSJ562KJDK23KD\n7YNEG7J3XBIVYR54' | totp
    546316
    942303

You can also provide the keys as arguments:

    $ totp 7KFSJ562KJDK23KD 7YNEG7J3XBIVYR54
    546316
    942303

By default it is assumed that the TOTP codes have a length of 6 and are valid
for 30 seconds.  You can change both of these parameters using the `-d` and `-p`
respectively, if required:

    $ totp -d8 -p60 7KFSJ562KJDK23KD 7YNEG7J3XBIVYR54
    71696020
    18335070

It might be useful however to instead use an OTP URI.  These are the URIs
embedded within 2-factor authentication QR codes, and often contain the metadata
specifying the length and period of the generated codes.  To use URIs, use the
`-u` flag:

    $ totp -u 'otpauth://totp/GitHub:Mango0x45?secret=7YNEG7J3XBIVYR54'
    942303

This also works with the standard input:

    $ echo 'otpauth://totp/GitHub:Mango0x45?secret=7YNEG7J3XBIVYR54' | totp -u
    942303

## Integration with `zbarimg`

`zbarimg` is a helpful CLI utility that we can use to get an OTP URI from a QR
code.  Here is an example of how we can use it to generate a TOTP code from a
2-factor authentication QR code:

    $ zbarimg -q qr-code.png | sed 's/QR-Code://' | totp
    546316


[1]: https://github.com/uriparser/uriparser

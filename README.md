# sendinblue/otp

OTP stands for One-Time Password: unique codes used as a form of two-factor authentication. Ways of generating such codes have been published by the [Initiative for Open Authentication](https://openauthentication.org/). This package provides classes implementing their algorithms.

## Installation

Open a command console, enter your project directory and execute the
following command to download the latest stable version of this library:

```console
$ composer require sendinblue/otp "~1"
```

This command requires you to have Composer installed globally, as explained
in the [installation chapter](https://getcomposer.org/doc/00-intro.md)
of the Composer documentation.

## OTP

`SendinBlue\Otp\Otp` is the base class of all OTP implementations, meaning each of them will define the following methods:

- `generate`: generates a OTP value
- `check`: checks a OTP value, throwing an `InvalidCodeException`
- `getBase32Secret`: returns the base32-encoded secret without padding

## HOTP ([RFC4226](https://tools.ietf.org/html/rfc4226))

You can handle HOTP values by extending the `SendinBlue\Otp\Hotp` class. You will have to implement the `getCurrentIndex` method to return the client current counter value. If you want the algorithm to be counter-based (this is probably what you want) then you are all set! If it is sequence-based you must also override the `getElement` method by returning the sequence element at a given index.

### Provisioning a client

For starters, most clients only support counter-based HOTP. You have been warned!

Your class will inherit the `getBase32Secret` method which is the simplest way for you: just display its return and let your user copy the value in his client. Be aware the smallest secret is 20 bytes long. The user will have to type at least 32 characters!

As a better alternative you can display the URL returned by `generateQRCodeUrl` as a QR Code to be scanned by an application like *FreeOTP Authenticator*. Do not use any public API like Google Chart API to generate QR Codes as the URL will contain the secret!

### Resynchronization

Your server must increment the counter each time a valid HOTP code is supplied whereas a client will increment the counter each time a new code is asked. This means client and server might be desynchronized. To allow resynchronization the `check` method lets you pass a look-ahead value as second argument and will return the difference between your server’s counter and the client’s. Be aware the biggest this value is, the less secure is the code.

## TOTP ([RFC6238](https://tools.ietf.org/html/rfc6238))

TOTP is simpler to use than HOTP because the counter is time-dependant, this means you can directly use the `SendinBlue\Otp\Totp` class. You can see its constructor offers many configuration options but unfortunately the defaults are probably the only ones you’ll use because some applications only support these defaults.

The only difference between HOTP and TOTP will concern the resynchronization: a client using TOTP can also be late compared to the server, so you may pass a look-behind **and** look-ahead value to the `check` method. As such it can return a negative value.

## OCRA ([RFC6287](https://tools.ietf.org/html/rfc6287))

Development is in progress on the [ocra branch](/tree/ocra).

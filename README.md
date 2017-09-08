FpdiProtection
=================================

[![Latest Stable Version](https://poser.pugx.org/setasign/fpdi-protection/v/stable.svg)](https://packagist.org/packages/setasign/fpdi-protection) [![Total Downloads](https://poser.pugx.org/setasign/fpdi-protection/downloads.svg)](https://packagist.org/packages/setasign/fpdi-protection) [![Latest Unstable Version](https://poser.pugx.org/setasign/fpdi-protection/v/unstable.svg)](https://packagist.org/packages/setasign/fpdi-protection) [![License](https://poser.pugx.org/setasign/fpdi-protection/license.svg)](https://packagist.org/packages/setasign/fpdi-protection)

A FPDI compatible and enhanced version of the [FPDF_Protection](http://www.fpdf.org/en/script/script37.php) script.

This version requires and uses OpenSSL functions instead of MCrypt or a user land implementation of RC4.

RC4-40bits and RC4-128bits encryption are supported.

## Installation with [Composer](https://packagist.org/packages/setasign/fpdi-protection)

```json
{
    "require": {
        "setasign/fpdi-protection": "^2.0"
    }
}
```
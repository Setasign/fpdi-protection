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

## Example

This class offers one public method, which allows you to set the protection of the resulting PDF document.
All other code is identically to FPDI or FPDF.

```php
<?php
use setasign\FpdiProtection\FpdiProtection;

// setup the autoload function
require_once('vendor/autoload.php');

$pdf = new FpdiProtection();
$pdf->setProtection(
    FpdiProtection::PERM_PRINT | FpdiProtection::PERM_COPY,
    'the user password',
    'the owner password'
);

// ...
```
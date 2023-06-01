<?php

namespace setasign\FpdiProtection\functional;

use PHPUnit\Framework\TestCase;
use Prophecy\Exception\InvalidArgumentException;
use setasign\Fpdi\Fpdi;
use setasign\Fpdi\PdfParser\CrossReference\CrossReference;
use setasign\Fpdi\PdfParser\Filter\AsciiHex;
use setasign\Fpdi\PdfParser\PdfParser;
use setasign\Fpdi\PdfParser\StreamReader;
use setasign\Fpdi\PdfParser\Type\PdfHexString;
use setasign\Fpdi\PdfParser\Type\PdfString;
use setasign\Fpdi\PdfReader\PdfReader;
use setasign\FpdiProtection\FpdiProtection;

class FpdiProtectionTest extends TestCase
{
    public function sanitizePermissionsValueProvider()
    {
        return [
            // array
            [
                [FpdiProtection::PERM_PRINT, FpdiProtection::PERM_COPY],
                2,
                -44
            ],
            [
                ['print', 'copy'],
                2,
                -44
            ],
            [
                FpdiProtection::PERM_PRINT | FpdiProtection::PERM_COPY,
                2,
                -44
            ],
            [
                [FpdiProtection::PERM_PRINT, FpdiProtection::PERM_COPY],
                3,
                -3884
            ],
            [
                FpdiProtection::PERM_PRINT | FpdiProtection::PERM_COPY,
                3,
                -3884
            ],
            // all but printing
            [
                (
                    FpdiProtection::PERM_COPY | FpdiProtection::PERM_ACCESSIBILITY | FpdiProtection::PERM_ANNOT |
                    FpdiProtection::PERM_ASSEMBLE | FpdiProtection::PERM_FILL_FORM | FpdiProtection::PERM_MODIFY
                ),
                3,
                -2056
            ],
            // no rights
            [
                0,
                3,
                -3904
            ]
        ];
    }

    /**
     * @param $value
     * @param $expectedValue
     * @dataProvider sanitizePermissionsValueProvider
     */
    public function testSanitizePermissionsValue($value, $revision, $expectedValue)
    {
        $pdf = new FpdiProtection();

        $this->assertSame($expectedValue, $pdf->sanitizePermissionsValue($value, $revision));
    }

    public function testSanitizePermissionsValueWithInvalidArgument()
    {
        $pdf = new FpdiProtection();
        $this->expectException(\InvalidArgumentException::class);
        $pdf->sanitizePermissionsValue(1, 3);
    }

    public function testSetProtectionWithInvalidRevision()
    {
        $pdf = new FpdiProtection();
        $this->expectException(\InvalidArgumentException::class);
        $pdf->setProtection([], '113pasS#', null, 1);
    }

    private function getEncryptionKey(FpdiProtection $pdf)
    {
        $reflection = new \ReflectionClass($pdf);
        $property = $reflection->getProperty('encryptionKey');
        $property->setAccessible(true);
        return $property->getValue($pdf);
    }

    private function calcKey($encryptionKey, $objectNumber, $revision = 3)
    {
        return substr(substr(md5($encryptionKey . pack('VXxx', $objectNumber), true), 0, ($revision === 3 ? 16 : 5) + 5), 0, 16);
    }

    public function testWithoutEncryption()
    {
        $pdf = new FpdiProtection();
        $pdf->AddPage();
        $pdf->setSourceFile(__DIR__ . '/../_files/pdfs/Noisy-Tube.pdf');
        $id = $pdf->importPage(1);
        $pdf->useTemplate($id, 30, 30, 100);

        $pdfString = $pdf->Output('S');

        $parser = new PdfParser(StreamReader::createByString($pdfString));
        $trailer = $parser->getCrossReference()->getTrailer();
        $this->assertFalse(isset($trailer->value['Encrypt']));
    }

    /**
     * This test imports a page and encrypts the result.
     * Then we extract the encryption key, use the PdfParser to extract the encrypted objects and decrypt it manually.
     * This test covers strings, hex-strings and streams.
     */
    public function testWithEncryptionRevision3()
    {
        $path = __DIR__ . '/../_files/pdfs/Noisy-Tube.pdf';
        $pdf = new FpdiProtection();

        $reflection = new \ReflectionClass($pdf);
        $method = $reflection->getMethod('getPdfReader');
        $method->setAccessible(true);

        $pdf->setProtection([], 'paSs123#', null);
        $pdf->AddPage();
        $pdf->setSourceFile($path);

        // Let's change a string value to HexString
        /**
         * @var PdfReader $reader
         */
        $reader = $method->invoke($pdf, realpath($path));
        $object22 = $reader->getParser()->getIndirectObject(22, true);
        $value = PdfString::unescape($object22->value->value['FontFamily']->value);
        $filter = new AsciiHex();
        $object22->value->value['FontFamily'] = PdfHexString::create($filter->encode($value));

        $id = $pdf->importPage(1);
        $pdf->useTemplate($id, 30, 30, 100);

        $pdfString = $pdf->Output('S');
        //file_put_contents('temp.pdf', $pdfString);

        $encryptionKey = $this->getEncryptionKey($pdf);

        $parser = $this->getMockBuilder(PdfParser::class)
            ->setConstructorArgs([StreamReader::createByString($pdfString)])
            ->setMethods(['getCrossReference'])
            ->getMock();

        $xref = $this->getMockBuilder(CrossReference::class)
            ->setConstructorArgs([$parser, 0])
            ->setMethods(['checkForEncryption'])
            ->getMock();

        $parser->method('getCrossReference')
            ->willReturn($xref);

        /**
         * @var PdfParser $parser
         */
        $trailer = $parser->getCrossReference()->getTrailer();

        $this->assertTrue(isset($trailer->value['Encrypt']));

        $encrypt = $parser->getIndirectObject($trailer->value['Encrypt']->value)->value->value;
        $this->assertSame(2, $encrypt['V']->value);
        $this->assertSame(3, $encrypt['R']->value);
        $this->assertSame(128, $encrypt['Length']->value);
        $this->assertSame(-3904, $encrypt['P']->value);

        // test a stream object
        $object5 = $parser->getIndirectObject(5);
        $stream = $object5->value->getStream();

        $realStream = gzuncompress(
            openssl_decrypt($stream, 'RC4-40', $this->calcKey($encryptionKey, 5),  OPENSSL_RAW_DATA)
        );

        $streamPrefix = "q\n/GS0 gs\n/Fm0 Do\nQ\nBT\n/CS0 cs 0.428 0.433 0.443  scn\n/GS0 gs\n";
        $this->assertStringStartsNotWith($stream, $realStream);
        $this->assertStringStartsWith($streamPrefix, $realStream);

        // test string in object 21
        $object21 = $parser->getIndirectObject(21);
        $fontFamily = PdfString::unescape($object21->value->value['FontFamily']->value);
        $realFontFamily = openssl_decrypt(
            $fontFamily, 'RC4-40', $this->calcKey($encryptionKey, 21),  OPENSSL_RAW_DATA
        );

        $this->assertEquals('GSBEM T+ Futura Std', $realFontFamily);

        // test hex-string in object 24
        $object24 = $parser->getIndirectObject(24);
        $fontFamily = $filter->decode($object24->value->value['FontFamily']->value);
        $realFontFamily = openssl_decrypt(
            $fontFamily, 'RC4-40', $this->calcKey($encryptionKey, 24),  OPENSSL_RAW_DATA
        );

        $this->assertEquals('Futura Std Medium', $realFontFamily);
    }

    /**
     * This test imports a page and encrypts the result.
     * Then we extract the encryption key, use the PdfParser to extract the encrypted objects and decrypt it manually.
     * This test covers strings, hex-strings and streams.
     */
    public function testWithEncryptionRevision2()
    {
        $path = __DIR__ . '/../_files/pdfs/Noisy-Tube.pdf';
        $pdf = new FpdiProtection();

        $reflection = new \ReflectionClass($pdf);
        $method = $reflection->getMethod('getPdfReader');
        $method->setAccessible(true);

        $pdf->setProtection([], 'paSs#123', null, 2);
        $pdf->AddPage();
        $pdf->setSourceFile($path);

        // Let's change a string value to HexString
        /**
         * @var PdfReader $reader
         */
        $reader = $method->invoke($pdf, realpath($path));
        $object22 = $reader->getParser()->getIndirectObject(22, true);
        $value = PdfString::unescape($object22->value->value['FontFamily']->value);
        $filter = new AsciiHex();
        $object22->value->value['FontFamily'] = PdfHexString::create($filter->encode($value));

        $id = $pdf->importPage(1);
        $pdf->useTemplate($id, 30, 30, 100);

        $pdfString = $pdf->Output('S');
        //file_put_contents('temp.pdf', $pdfString);

        $encryptionKey = $this->getEncryptionKey($pdf);

        $parser = $this->getMockBuilder(PdfParser::class)
            ->setConstructorArgs([StreamReader::createByString($pdfString)])
            ->setMethods(['getCrossReference'])
            ->getMock();

        $xref = $this->getMockBuilder(CrossReference::class)
            ->setConstructorArgs([$parser, 0])
            ->setMethods(['checkForEncryption'])
            ->getMock();

        $parser->method('getCrossReference')
            ->willReturn($xref);

        /**
         * @var PdfParser $parser
         */
        $trailer = $parser->getCrossReference()->getTrailer();

        $this->assertTrue(isset($trailer->value['Encrypt']));

        $encrypt = $parser->getIndirectObject($trailer->value['Encrypt']->value)->value->value;
        $this->assertSame(1, $encrypt['V']->value);
        $this->assertSame(2, $encrypt['R']->value);
        $this->assertSame(-64, $encrypt['P']->value);

        // test a stream object
        $object5 = $parser->getIndirectObject(5);
        $stream = $object5->value->getStream();

        $realStream = gzuncompress(
            openssl_decrypt($stream, 'RC4-40', $this->calcKey($encryptionKey, 5, 2),  OPENSSL_RAW_DATA)
        );

        $streamPrefix = "q\n/GS0 gs\n/Fm0 Do\nQ\nBT\n/CS0 cs 0.428 0.433 0.443  scn\n/GS0 gs\n";
        $this->assertStringStartsNotWith($stream, $realStream);
        $this->assertStringStartsWith($streamPrefix, $realStream);

        // test string in object 21
        $object21 = $parser->getIndirectObject(21);
        $fontFamily = PdfString::unescape($object21->value->value['FontFamily']->value);
        $realFontFamily = openssl_decrypt(
            $fontFamily, 'RC4-40', $this->calcKey($encryptionKey, 21, 2),  OPENSSL_RAW_DATA
        );

        $this->assertEquals('GSBEM T+ Futura Std', $realFontFamily);

        // test hex-string in object 24
        $object24 = $parser->getIndirectObject(24);
        $fontFamily = $filter->decode($object24->value->value['FontFamily']->value);
        $realFontFamily = openssl_decrypt(
            $fontFamily, 'RC4-40', $this->calcKey($encryptionKey, 24, 2),  OPENSSL_RAW_DATA
        );

        $this->assertEquals('Futura Std Medium', $realFontFamily);
    }

    public function testPdfVersionChange()
    {
        $pdf = new FpdiProtection();
        $pdfString = $pdf->Output('S');
        $this->assertStringStartsWith('%PDF-1.3', $pdfString);

        $pdf = new FpdiProtection();
        $pdf->setProtection([], 'Pass1@#', null, 2);
        $pdfString = $pdf->Output('S');
        $this->assertStringStartsWith('%PDF-1.3', $pdfString);

        $pdf = new FpdiProtection();
        $pdf->setProtection([], 'Pass1@#', null, 3);
        $pdfString = $pdf->Output('S');
        $this->assertStringStartsWith('%PDF-1.4', $pdfString);
    }

    public function testLinks()
    {
        $linkTarget = 'https://setasign.com';
        $pdf = new FpdiProtection();
        $pdf->setProtection([], 'User12@2', 'Owner12@23', 3);
        $pdf->AddPage();
        $pdf->SetFont('Helvetica', '', 12);
        $pdf->Cell(0, 10, 'Test', 0, 0, '', false, $linkTarget);

        $encryptionKey = $this->getEncryptionKey($pdf);

        $pdfString = $pdf->Output('S');

        // let's extract the object manually and parse it into a object structre
        preg_match('~5 0 obj(.*?)endobj~s', $pdfString, $match);
        $parser = new PdfParser(StreamReader::createByString($match[1]));
        $value = $parser->readValue();

        $uri = PdfString::unescape($value->value['A']->value['URI']->value);

        $uri = openssl_decrypt(
            $uri, 'RC4-40', $this->calcKey($encryptionKey, 5, 3),  OPENSSL_RAW_DATA
        );

        $this->assertEquals($linkTarget, $uri);
    }

    protected function isPasswordStrong($password)
    {
        // Password should be at least 6 characters long
        if (strlen($password) < 6) {
            return false;
        }

        // Password should contain at least one uppercase letter
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }

        // Password should contain at least one lowercase letter
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }

        // Password should contain at least one digit
        if (!preg_match('/\d/', $password)) {
            return false;
        }

        // Password should contain at least one special character
        if (!preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
            return false;
        }

        // All checks passed, password is strong
        return true;
    }
    public function testPasswordStrength()
    {
        // Test a strong password
        $strongPassword = "StrongPass123!";
        $this->assertTrue($this->isPasswordStrong($strongPassword));

        // Test a password with less than 8 characters
        $shortPassword = "short";
        $this->assertFalse($this->isPasswordStrong($shortPassword));

        // Test a password without an uppercase letter
        $noUppercasePassword = "weakpassword123!";
        $this->assertFalse($this->isPasswordStrong($noUppercasePassword));

        // Test a password without a lowercase letter
        $noLowercasePassword = "WEAKPASSWORD123!";
        $this->assertFalse($this->isPasswordStrong($noLowercasePassword));

        // Test a password without a digit
        $noDigitPassword = "WeakPassword!";
        $this->assertFalse($this->isPasswordStrong($noDigitPassword));

        // Test a password without a special character
        $noSpecialCharPassword = "WeakPassword123";
        $this->assertFalse($this->isPasswordStrong($noSpecialCharPassword));
    }
}

<?php
/**
 * This file is part of FpdiProtection
 *
 * @package   setasign\FpdiProtection
 * @copyright Copyright (c) 2017 Setasign - Jan Slabon (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 * @version   2.0.0
 */

namespace setasign\FpdiProtection;

use setasign\Fpdi\PdfParser\Filter\AsciiHex;
use setasign\Fpdi\PdfParser\Type\PdfHexString;
use setasign\Fpdi\PdfParser\Type\PdfNumeric;
use setasign\Fpdi\PdfParser\Type\PdfStream;
use setasign\Fpdi\PdfParser\Type\PdfString;
use setasign\Fpdi\PdfParser\Type\PdfType;

/**
 * Class FpdiProtection
 *
 * @package setasign\FpdiProtection
 */
class FpdiProtection extends \setasign\Fpdi\Fpdi
{
    /**
     * Whether document is protected or not
     *
     * @var bool
     */
    protected $encrypted = false;

    /**
     * U entry in pdf document
     *
     * @var string
     */
    protected $uValue;

    /**
     * O entry in pdf document
     *
     * @var string
     */
    protected $oValue;

    /**
     * P entry in pdf document
     *
     * @var string
     */
    protected $pValue;

    /**
     * The encryption object number
     *
     * @var integer
     */
    protected $encObjectNumber;

    /**
     * The encryption key
     *
     * @var string
     */
    protected $encryptionKey;

    /**
     * The padding string
     *
     * @var string
     */
    protected $padding;

    /**
     * The current written object number
     *
     * @var integer
     */
    protected $currentObjectNumber;

    /**
     * @var string
     */
    protected $fileIdentifier;

    public function __construct($orientation = 'P', $unit = 'mm', $size = 'A4')
    {
        parent::__construct($orientation, $unit, $size);
        $randomBytes = function_exists('random_bytes') ? \random_bytes(32) : \mt_rand();
        $this->fileIdentifier = md5(__FILE__ . \php_sapi_name() . \phpversion() . $randomBytes, true);
    }

    /**
     * Set permissions as well as user and owner passwords
     *
     * @param array $permissions An array with values taken from the following list: copy, print, modify, annot-forms
     *                           If a value is present it means that the permission is granted
     * @param string $userPass If a user password is set, user will be prompted before document is opened
     * @param null $ownerPass If an owner password is set, document can be opened in privilege mode with no
     *                        restriction if that password is entered
     */
    public function SetProtection(array $permissions = [], $userPass = '', $ownerPass = null)
    {
        $options = ['print' => 4, 'modify' => 8, 'copy' => 16, 'annot-forms' => 32];
        $protection = 192;
        foreach ($permissions as $permission)
        {
            if (!isset($options[$permission])) {
                throw new \InvalidArgumentException('Incorrect permission: ' . $permission);
            }
            $protection += $options[$permission];
        }

        if ($ownerPass === null) {
            $ownerPass = uniqid(rand());
        }

        $this->encrypted = true;
        $this->padding = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08"
            . "\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
        $this->_generateencryptionkey($userPass, $ownerPass, $protection);
    }

    protected function _putstream($s)
    {
        if ($this->encrypted) {
            $s = $this->_arcfour($this->_objectkey($this->n), $s);
        }

        parent::_putstream($s);
    }

    protected function _textstring($s)
    {
        if (!$this->_isascii($s)) {
            $s = $this->_UTF8toUTF16($s);
        }

        if ($this->encrypted) {
            $s = $this->_arcfour($this->_objectkey($this->n), $s);
        }

        return '(' . $this->_escape($s) . ')';
    }

    /**
     * Compute key depending on object number where the encrypted data is stored
     */
    protected function _objectkey($n)
    {
        return substr(md5($this->encryptionKey . pack('VXxx', $n), true), 0, 10);
    }

    protected function _putresources()
    {
        parent::_putresources();
        if ($this->encrypted) {
            $this->_newobj();
            $this->encObjectNumber = $this->n;
            $this->_put('<<');
            $this->_putencryption();
            $this->_put('>>');
            $this->_put('endobj');
        }
    }

    protected function _putencryption()
    {
        $this->_put('/Filter /Standard');
        $this->_put('/V 1');
        $this->_put('/R 2');
        $this->_put('/O (' . $this->_escape($this->oValue) . ')');
        $this->_put('/U (' . $this->_escape($this->uValue) . ')');
        $this->_put('/P ' . $this->pValue);
    }

    protected function _puttrailer()
    {
        parent::_puttrailer();
        if ($this->encrypted) {
            $this->_put('/Encrypt ' . $this->encObjectNumber . ' 0 R');
            $filter = new AsciiHex();
            $fileIdentifier = $filter->encode($this->fileIdentifier, true);
            $this->_put('/ID [<' . $fileIdentifier . '><' . $fileIdentifier . '>]');
        }
    }

    /**
     * Compute O value
     */
    protected function _createOValue($userPass, $ownerPass)
    {
        $tmp = md5($ownerPass, true);
        $ownerArcfourKey = substr($tmp, 0, 5);
        return $this->_arcfour($ownerArcfourKey, $userPass);
    }

    /**
     * Compute U value
     */
    protected function _createUValue()
    {
        return $this->_arcfour($this->encryptionKey, $this->padding);
    }

    /**
     * Compute encryption key
     */
    protected function _generateencryptionkey($userPass, $ownerPass, $protection)
    {
        // Pad passwords
        $userPass = substr($userPass . $this->padding, 0, 32);
        $ownerPass = substr($ownerPass . $this->padding, 0, 32);
        // Compute O value
        $this->oValue = $this->_createOValue($userPass, $ownerPass);
        // Compute encyption key
        $tmp = md5($userPass . $this->oValue . chr($protection) . "\xFF\xFF\xFF" . $this->fileIdentifier, true);
        $this->encryptionKey = substr($tmp, 0, 5);
        // Compute U value
        $this->uValue = $this->_createUValue();
        // Compute P value
        $this->pValue = -(($protection ^ 255) + 1);
    }

    protected function _arcfour($key, $data)
    {
        return openssl_encrypt($data, 'RC4-40', $key, OPENSSL_RAW_DATA, '');
    }

    /**
     * Writes a PdfType object to the resulting buffer.
     *
     * @param PdfType $value
     */
    protected function writePdfType(PdfType $value)
    {
        if (!$this->encrypted) {
            parent::writePdfType($value);
            return;
        }

        if ($value instanceof PdfString) {
            $string = PdfString::unescape($value->value);
            $string = $this->_arcfour($this->_objectkey($this->currentObjectNumber), $string);
            $value->value = $this->_escape($string);

        } elseif ($value instanceof PdfHexString) {
            $filter = new AsciiHex();
            $string = $filter->decode($value->value);
            $string = $this->_arcfour($this->_objectkey($this->currentObjectNumber), $string);
            $value->value = $filter->encode($string, true);

        } elseif ($value instanceof PdfStream) {
            $stream = $value->getStream();
            $stream = $this->_arcfour($this->_objectkey($this->currentObjectNumber), $stream);
            $dictionary = $value->value;
            $dictionary->value['Length'] = PdfNumeric::create(strlen($stream));
            $value = PdfStream::create($dictionary, $stream);
        }

        parent::writePdfType($value);
    }

    protected function _newobj($n = null)
    {
        parent::_newobj($n);
        if ($n === null) {
            $this->currentObjectNumber = $this->n;
        } else {
            $this->currentObjectNumber = $n;
        }
    }
}
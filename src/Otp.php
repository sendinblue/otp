<?php

namespace SendinBlue\Otp;

use SendinBlue\Base32;
use SendinBlue\Otp\Exception\InvalidCodeException;

abstract class Otp
{
    /** @var string */
    protected $hmacAlgorithm;

    /** @var string */
    protected $secret;

    /** @var int */
    protected $outputLength;

    /**
     * @param string $hmacAlgorithm
     * @param string $secret
     * @param int    $outputLength
     */
    public function __construct($hmacAlgorithm, $secret, $outputLength)
    {
        if (strlen($secret) < 20) {
            throw new \DomainException('Secret must be at least 20 bytes long.');
        }

        if ($outputLength < 6 || $outputLength > 8) {
            throw new \DomainException('Codes must be between 6 and 8 characters long.');
        }

        $this->hmacAlgorithm = $hmacAlgorithm;
        $this->secret = $secret;
        $this->outputLength = $outputLength;
    }

    /**
     * @return string
     */
    public function getBase32Secret()
    {
        return Base32::encode($this->secret, false);
    }

    /**
     * @return string
     */
    abstract public function generate();

    /**
     * @param string $code
     *
     * @throws InvalidCodeException
     */
    public function check($code)
    {
        if (!hash_equals($this->generate(), $code)) {
            throw new InvalidCodeException();
        }
    }

    /**
     * @param string $input
     *
     * @return string
     */
    protected function hmac($input)
    {
        $hs = hash_hmac($this->hmacAlgorithm, $input, $this->secret, true);

        if (!$this->outputLength) {
            return $hs;
        }

        $offset = ord(substr($hs, -1)) & 0xF;
        $sNum = unpack('N*', substr($hs, $offset, 4))[1] & 0x7FFFFFFF;

        return str_pad($sNum % 10 ** $this->outputLength, $this->outputLength, '0', STR_PAD_LEFT);
    }
}

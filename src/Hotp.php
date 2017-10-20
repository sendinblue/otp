<?php

namespace SendinBlue\Otp;

use SendinBlue\Otp\Exception\InvalidCodeException;

abstract class Hotp extends Otp
{
    /**
     * @param string $secret
     * @param int    $outputLength
     */
    public function __construct($secret, $outputLength = 6)
    {
        parent::__construct('sha1', $secret, $outputLength);
    }

    /**
     * @return int
     */
    abstract public function getCurrentIndex();

    /**
     * @param int $index
     *
     * @return mixed
     */
    public function getElement($index)
    {
        return $index;
    }

    /**
     * {@inheritdoc}
     */
    public function generate()
    {
        return $this->hmac(pack('J', $this->getElement($this->getCurrentIndex())));
    }

    /**
     * @param string $code
     * @param int    $ahead
     *
     * @return int
     *
     * @throws InvalidCodeException
     */
    public function check($code, $ahead = 0)
    {
        $currentIndex = $this->getCurrentIndex();

        for ($i = $currentIndex, $until = $currentIndex + $ahead; $i <= $until; ++$i) {
            if (hash_equals($this->hmac(pack('J', $this->getElement($i))), $code)) {
                return $i - $currentIndex;
            }
        }

        throw new InvalidCodeException();
    }

    /**
     * @param string      $account
     * @param string|null $issuer
     * @param int         $counter
     *
     * @return string
     */
    public function generateQRCodeUrl($account, $issuer = null, $counter = 0)
    {
        if ($issuer) {
            $account = "{$issuer}:{$account}";
        }

        return 'otpauth://hotp/'.urlencode($account).'?'.http_build_query([
            'counter' => $counter,
            'digits' => $this->outputLength,
            'issuer' => $issuer,
            'secret' => $this->getBase32Secret(),
        ]);
    }
}

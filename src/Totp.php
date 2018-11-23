<?php

namespace SendinBlue\Otp;

use SendinBlue\Otp\Exception\InvalidCodeException;

class Totp extends Otp
{
    const ALLOWED_HMAC_ALGORITHMS = ['sha1', 'sha256', 'sha512'];

    /** @var int */
    private $timeReference;

    /** @var int */
    private $timeStep;

    /**
     * @param string $secret
     * @param int    $outputLength
     * @param string $hmacAlgorithm
     * @param int    $timeStep
     * @param int    $timeReference
     */
    public function __construct($secret, $outputLength = 6, $hmacAlgorithm = 'sha1', $timeStep = 30, $timeReference = 0)
    {
        if (!\in_array($hmacAlgorithm, self::ALLOWED_HMAC_ALGORITHMS, true)) {
            throw new \DomainException(sprintf('Algorithm must be one of %s', implode(', ', self::ALLOWED_HMAC_ALGORITHMS)));
        }

        if ($timeStep <= 0) {
            throw new \DomainException('Time step must be greater than zero');
        }

        parent::__construct($hmacAlgorithm, $secret, $outputLength);

        $this->timeReference = $timeReference;
        $this->timeStep = $timeStep;
    }

    /**
     * @return int
     */
    public function getCurrentTimeStep()
    {
        return (int) floor((time() - $this->timeReference) / $this->timeStep);
    }

    /**
     * {@inheritdoc}
     */
    public function generate()
    {
        return $this->hmac(pack('J', $this->getCurrentTimeStep()));
    }

    /**
     * @param string $code
     * @param int    $behind
     * @param int    $ahead
     *
     * @return int
     *
     * @throws InvalidCodeException
     */
    public function check($code, $behind = 0, $ahead = 0)
    {
        $t = $this->getCurrentTimeStep();

        for ($i = $t - $behind, $until = $t + $ahead; $i <= $until; ++$i) {
            if (hash_equals($this->hmac(pack('J', $i)), $code)) {
                return $i - $t;
            }
        }

        throw new InvalidCodeException();
    }

    /**
     * @param string      $account
     * @param string|null $issuer
     *
     * @return string
     */
    public function generateQRCodeUrl($account, $issuer = null)
    {
        if ($issuer) {
            $account = "{$issuer}:{$account}";
        }

        return 'otpauth://totp/'.urlencode($account).'?'.http_build_query([
            'algorithm' => $this->hmacAlgorithm,
            'digits' => $this->outputLength,
            'issuer' => $issuer,
            'period' => $this->timeStep,
            'secret' => $this->getBase32Secret(),
        ]);
    }
}

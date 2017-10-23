<?php

namespace SendinBlue\Otp;

abstract class Ocra extends Otp
{
    /** @var string */
    private $suite;

    /** @var bool */
    private $useCounter;

    /** @var string */
    private $challengeFormat;

    /** @var int */
    private $challengeMaxLength;

    /** @var string */
    private $passwordAlgorithm;

    /** @var int */
    private $sessionLength;

    /** @var int|null */
    private $timeStep;

    /**
     * @param string $secret
     * @param string $suite
     */
    public function __construct($secret, $suite)
    {
        if (strlen($secret) < 20) {
            throw new \DomainException('Secret must be at least 128 bits long');
        }

        $this->secret = $secret;

        $this->parseSuite($suite);
    }

    /**
     * @return mixed
     */
    abstract protected function getCounter();

    /**
     * @return mixed
     */
    abstract protected function getChallenge();

    /**
     * @return string
     */
    abstract protected function getPassword();

    /**
     * @return string
     */
    abstract protected function getSessionData();

    /**
     * {@inheritdoc}
     */
    public function generate()
    {
        $null = chr(0);
        $dataInput = $this->suite.$null;

        if ($this->useCounter) {
            $dataInput .= pack('J', $this->getCounter());
        }

        switch ($this->challengeFormat) {
            case 'A':
                $questions = (string) $this->getChallenge();
                break;
            case 'N':
                $questions = pack('H*', dechex($this->getChallenge()));
                break;
            case 'H':
                $questions = pack('H*', $this->getChallenge());
                break;
            default:
                throw new \DomainException('Invalid challenge format');
        }

        $dataInput .= str_pad($questions, 128, $null, STR_PAD_RIGHT);

        if ($this->passwordAlgorithm) {
            $dataInput .= hash($this->passwordAlgorithm, $this->getPassword(), true);
        }

        if ($this->sessionLength) {
            $dataInput .= $this->getSessionData();
        }

        if ($this->timeStep) {
            $dataInput .= pack('J', floor(time() / $this->timeStep));
        }

        return $this->hmac($dataInput);
    }

    /**
     * @see https://tools.ietf.org/html/rfc6287#section-6
     *
     * @param string $suite
     *
     * @throws \DomainException
     */
    private function parseSuite($suite)
    {
        $components = explode(':', $suite);
        if (3 !== count($components)) {
            throw new \DomainException('Invalid suite');
        }

        list($algorithm, $cryptoFunction, $dataInput) = $components;

        if ('OCRA-1' !== $algorithm) {
            throw new \DomainException('Invalid algorithm.');
        }

        $cryptoFunctionMatches = [];
        if (!preg_match('/^HOTP-SHA(?<shaNumber>1|256|512)-(?<digit>1?0|[4-9])$/', $cryptoFunction, $cryptoFunctionMatches)) {
            throw new \DomainException('Invalid cryptography function.');
        }

        $dataInputMatches = [];
        if (!preg_match('/^(?<counter>C-)?Q(?<challengeFormat>A|N|H)(?<challengeMaxLength>0[4-9]|6[0-4]|[1-5]\d)(-PSHA(?<passwordShaNumber>1|256|512))?(-S(?<sessionLength>[0-4]\d{2}|50\d|51[0-2]))?(-T(?<timeStep>([1-9]|[1-5]\d)(S|M)|([1-9]|[1-3]\d|4[0-8])H))?$/', $dataInput, $dataInputMatches)) {
            throw new \DomainException('Invalid data input.');
        }

        $this->suite = $suite;

        $this->hmacAlgorithm = "sha{$cryptoFunctionMatches['shaNumber']}";
        $this->outputLength = (int) $cryptoFunctionMatches['digit'];

        $this->useCounter = !empty($dataInputMatches['counter']);
        $this->challengeFormat = $dataInputMatches['challengeFormat'];
        $this->challengeMaxLength = (int) $dataInputMatches['challengeMaxLength'];

        if (!empty($dataInputMatches['passwordShaNumber'])) {
            $this->passwordAlgorithm = "sha{$dataInputMatches['passwordShaNumber']}";
        }

        if (!empty($dataInputMatches['sessionLength'])) {
            $this->sessionLength = (int) $dataInputMatches['sessionLength'];
        }

        if (!empty($dataInputMatches['timeStep'])) {
            $this->timeStep = (int) $dataInputMatches['timeStep'] * ['S' => 1, 'M' => 60, 'H' => 3600][substr($dataInputMatches['timeStep'], -1)];
        }
    }
}

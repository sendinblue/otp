<?php

namespace SendinBlue\Tests;

use SendinBlue\Otp\Exception\InvalidCodeException;
use SendinBlue\Otp\Totp;

class TotpTest extends \PHPUnit_Framework_TestCase
{
    public static $now;

    public function testAlgorithms()
    {
        new Totp('12345678901234567890', 6, 'sha1');
        new Totp('12345678901234567890', 6, 'sha256');
        new Totp('12345678901234567890', 6, 'sha512');

        $this->expectException(\DomainException::class);
        new Totp('12345678901234567890', 6, 'whirlpool');
    }

    public function testMinTimeStep()
    {
        $this->expectException(\DomainException::class);
        new Totp('12345678901234567890', 6, 'sha1', 0);
    }

    public function testTimeStep()
    {
        $totp = new Totp('12345678901234567890');

        self::$now = 59;
        $this->assertSame(1, $totp->getCurrentTimeStep());

        self::$now = 1111111109;
        $this->assertSame(37037036, $totp->getCurrentTimeStep());

        self::$now = 1111111111;
        $this->assertSame(37037037, $totp->getCurrentTimeStep());

        self::$now = 1234567890;
        $this->assertSame(41152263, $totp->getCurrentTimeStep());

        self::$now = 2000000000;
        $this->assertSame(66666666, $totp->getCurrentTimeStep());

        self::$now = 20000000000;
        $this->assertSame(666666666, $totp->getCurrentTimeStep());
    }

    public function testGenerate()
    {
        $sha1 = new Totp('12345678901234567890', 8, 'sha1');
        $sha256 = new Totp('12345678901234567890123456789012', 8, 'sha256');
        $sha512 = new Totp('1234567890123456789012345678901234567890123456789012345678901234', 8, 'sha512');

        self::$now = 59;
        $this->assertSame('94287082', $sha1->generate());
        $this->assertSame('46119246', $sha256->generate());
        $this->assertSame('90693936', $sha512->generate());

        self::$now = 1111111109;
        $this->assertSame('07081804', $sha1->generate());
        $this->assertSame('68084774', $sha256->generate());
        $this->assertSame('25091201', $sha512->generate());

        self::$now = 1111111111;
        $this->assertSame('14050471', $sha1->generate());
        $this->assertSame('67062674', $sha256->generate());
        $this->assertSame('99943326', $sha512->generate());

        self::$now = 1234567890;
        $this->assertSame('89005924', $sha1->generate());
        $this->assertSame('91819424', $sha256->generate());
        $this->assertSame('93441116', $sha512->generate());

        self::$now = 2000000000;
        $this->assertSame('69279037', $sha1->generate());
        $this->assertSame('90698825', $sha256->generate());
        $this->assertSame('38618901', $sha512->generate());

        self::$now = 20000000000;
        $this->assertSame('65353130', $sha1->generate());
        $this->assertSame('77737706', $sha256->generate());
        $this->assertSame('47863826', $sha512->generate());
    }

    public function testCheck()
    {
        $totp = new Totp('12345678901234567890', 8, 'sha1');

        self::$now = 1111111109;
        $this->assertSame(0, $totp->check('07081804'));
        $this->assertSame(1, $totp->check('14050471', 0, 1));

        $this->expectException(InvalidCodeException::class);
        $totp->check('14050471');
    }

    public function testQRCodeUrl()
    {
        $totp = new Totp('12345678901234567890');

        $components = parse_url($totp->generateQRCodeUrl('account'));
        parse_str($components['query'], $parameters);
        $this->assertSame('otpauth', $components['scheme']);
        $this->assertSame('totp', $components['host']);
        $this->assertSame('/account', $components['path']);
        $this->assertEquals([
            'digits' => 6,
            'secret' => $totp->getBase32Secret(),
            'algorithm' => 'sha1',
            'period' => 30,
        ], $parameters);

        $components = parse_url($totp->generateQRCodeUrl('account', 'issuer'));
        parse_str($components['query'], $parameters);
        $this->assertSame('/issuer%3Aaccount', $components['path']);
        $this->assertArraySubset([
            'issuer' => 'issuer',
        ], $parameters);
    }
}

namespace SendinBlue\Otp;

use SendinBlue\Tests\TotpTest;

function time()
{
    return TotpTest::$now ?: \time();
}

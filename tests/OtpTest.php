<?php

namespace SendinBlue\Tests;

use SendinBlue\Otp\Otp;

class OtpTest extends \PHPUnit_Framework_TestCase
{
    public function testMinSecretLength()
    {
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(20), 6]);

        $this->expectException(\DomainException::class);
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(19), 6]);
    }

    public function testMinOutputLength()
    {
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(20), 6]);

        $this->expectException(\DomainException::class);
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(20), 5]);
    }

    public function testMaxOutputLength()
    {
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(20), 8]);

        $this->expectException(\DomainException::class);
        $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(20), 9]);
    }

    public function testBase32SecretHasNoPadding()
    {
        $stub = $this->getMockForAbstractClass(Otp::class, ['sha1', random_bytes(21), 6]);
        $this->assertStringEndsNotWith('=', $stub->getBase32Secret());
    }
}

<?php

namespace SendinBlue\Tests;

use SendinBlue\Otp\Exception\InvalidCodeException;
use SendinBlue\Otp\Hotp;

class HotpTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $stub = $this->getMockForAbstractClass(Hotp::class, ['12345678901234567890']);

        $getCurrentIndex = $stub->method('getCurrentIndex');

        foreach (['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'] as $count => $otp) {
            $getCurrentIndex->willReturn($count);
            $this->assertSame($otp, $stub->generate());
        }
    }

    public function testCheck()
    {
        $stub = $this->getMockForAbstractClass(Hotp::class, ['12345678901234567890']);

        $getCurrentIndex = $stub->method('getCurrentIndex');

        foreach (['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'] as $count => $otp) {
            $getCurrentIndex->willReturn($count);
            $this->assertSame(0, $stub->check($otp));
        }

        $getCurrentIndex->willReturn(0);
        $this->assertSame(1, $stub->check('287082', 1));

        $this->expectException(InvalidCodeException::class);
        $stub->check('287082');
    }

    public function testQRCodeUrl()
    {
        $stub = $this->getMockForAbstractClass(Hotp::class, ['12345678901234567890']);

        $components = parse_url($stub->generateQRCodeUrl('account'));
        parse_str($components['query'], $parameters);
        $this->assertSame('otpauth', $components['scheme']);
        $this->assertSame('hotp', $components['host']);
        $this->assertSame('/account', $components['path']);
        $this->assertEquals([
            'counter' => 0,
            'digits' => 6,
            'secret' => $stub->getBase32Secret(),
        ], $parameters);

        $components = parse_url($stub->generateQRCodeUrl('account', 'issuer'));
        parse_str($components['query'], $parameters);
        $this->assertSame('/issuer%3Aaccount', $components['path']);
        $this->assertArraySubset([
            'issuer' => 'issuer',
        ], $parameters);

        parse_str(parse_url($stub->generateQRCodeUrl('account', 'issuer', 1), PHP_URL_QUERY), $parameters);
        $this->assertArraySubset([
            'counter' => 1,
        ], $parameters);
    }
}

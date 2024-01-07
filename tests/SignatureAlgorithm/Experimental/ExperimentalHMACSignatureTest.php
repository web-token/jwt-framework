<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\Experimental;

use Jose\Component\Core\JWK;
use Jose\Experimental\Signature\HS1;
use Jose\Experimental\Signature\HS256_64;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class ExperimentalHMACSignatureTest extends TestCase
{
    #[Test]
    public function hS1SignAndVerify(): void
    {
        $key = $this->getKey();
        $hmac = new HS1();
        $data = 'Live long and Prosper.';

        static::assertSame('HS1', $hmac->name());

        $signature = $hmac->hash($key, $data);

        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    #[Test]
    public function hS256SignAndVerify(): void
    {
        $key = $this->getKey();
        $hmac = new HS256_64();
        $data = 'Live long and Prosper.';

        static::assertSame('HS256/64', $hmac->name());

        $signature = $hmac->hash($key, $data);

        static::assertSame(hex2bin('89f750759cb8ad93'), $signature);
        static::assertTrue($hmac->verify($key, $data, $signature));
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'foo',
        ]);
    }
}

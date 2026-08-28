<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\Experimental;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ECDSA;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Experimental\Signature\BP256R1;
use Jose\Experimental\Signature\BP384R1;
use Jose\Experimental\Signature\BP512R1;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * @internal
 */
final class BrainpoolSignatureTest extends TestCase
{
    private const MESSAGE = 'Live long and prosper.';

    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmIsCorrectlyIdentified(ECDSA $algorithm, string $name): void
    {
        static::assertSame($name, $algorithm->name());
        static::assertSame(['EC'], $algorithm->allowedKeyTypes());
    }

    /**
     * The signatures were produced by OpenSSL with the very same keys.
     *
     * @param array{crv: string, d: string, x: string, y: string} $key
     */
    #[Test]
    #[DataProvider('signatureVectors')]
    public function aSignatureProducedByOpensslIsVerified(ECDSA $algorithm, array $key, string $signature): void
    {
        $rawSignature = hex2bin($signature);
        static::assertIsString($rawSignature);

        static::assertTrue($algorithm->verify(self::createKey($key), self::MESSAGE, $rawSignature));
    }

    /**
     * @param array{crv: string, d: string, x: string, y: string} $key
     */
    #[Test]
    #[DataProvider('signatureVectors')]
    public function aSignatureIsProducedAndVerified(ECDSA $algorithm, array $key, string $signature): void
    {
        $jwk = self::createKey($key);

        $newSignature = $algorithm->sign($jwk, self::MESSAGE);

        static::assertSame(intdiv(strlen($signature), 2), strlen($newSignature));
        static::assertTrue($algorithm->verify($jwk->toPublic(), self::MESSAGE, $newSignature));
        static::assertFalse($algorithm->verify($jwk->toPublic(), 'Another message', $newSignature));
    }

    /**
     * @param array{crv: string, d: string, x: string, y: string} $key
     */
    #[Test]
    #[DataProvider('signatureVectors')]
    public function aTokenIsSignedAndVerified(ECDSA $algorithm, array $key, string $signature): void
    {
        $jwk = self::createKey($key);
        $algorithmManager = new AlgorithmManager([$algorithm]);
        $serializer = new CompactSerializer();

        $jws = (new JWSBuilder($algorithmManager))
            ->withPayload(self::MESSAGE)
            ->addSignature($jwk, [
                'alg' => $algorithm->name(),
            ])
            ->build();
        $token = $serializer->serialize($jws);

        $loaded = $serializer->unserialize($token);

        static::assertSame(self::MESSAGE, $loaded->getPayload());
        static::assertSame(intdiv(strlen($signature), 2), strlen($loaded->getSignature(0)->getSignature()));
        static::assertTrue((new JWSVerifier($algorithmManager))->verifyWithKey($loaded, $jwk->toPublic(), 0));
    }

    /**
     * @return iterable<string, array{ECDSA, string}>
     */
    public static function algorithms(): iterable
    {
        yield 'BP256R1' => [new BP256R1(), 'BP256R1'];
        yield 'BP384R1' => [new BP384R1(), 'BP384R1'];
        yield 'BP512R1' => [new BP512R1(), 'BP512R1'];
    }

    /**
     * @return iterable<string, array{ECDSA, array{crv: string, d: string, x: string, y: string}, string}>
     */
    public static function signatureVectors(): iterable
    {
        yield 'BP256R1' => [
            new BP256R1(),
            [
                'crv' => 'BP-256',
                'd' => 'LO519MROm0ZfNb7_rFziwfWAOGOikyL_TWcFgxC2QGs',
                'x' => 'bc9FkWgnIkE-0ItBLphZhfvgWJhMHbzDiv8ZdHT7XTU',
                'y' => 'KAbchpoiAwslepU0sonfI7N5kWoSbeKtwgANkHtQZPE',
            ],
            '7455ccc0443eb9614d191c1ad21b4ded58027c260054ea86fed1b1ad1bf8583a'
            . '5aa8ccfc4f70ba14519da6ce6ca38c70f1e825fddfdfb98c52b19eb5495c0703',
        ];

        yield 'BP384R1' => [
            new BP384R1(),
            [
                'crv' => 'BP-384',
                'd' => 'CgHMFMY5osJkc3ZrFZqF9Geea5o-eAS0oewVM9wppu3K_yOEvn1BvjkpwUu5-CF_',
                'x' => 'h4aoH5jXljRZscmdXzhsmkzjEfBzedyKyScCp4rt43_nIkJ4CpWmMJLuRb1DZQtB',
                'y' => 'g1ilNpDXY2vMC56IYrHreKbr5i4n8hD8dDXRjU2djh19XZmoM13sSY6QJBSMg1mZ',
            ],
            '12235d2680b9a286a1c1700f6ef8b9fe8434abef06b7913b24fb482573399739'
            . '8e063480bd4d82ebb8d71c3ca64071a53106bca4e777b00b00175a6bb97c1c5d'
            . 'c1be9a7f1a84e14fb157a95a3c1f7298013f437a6589003b9dea5c293fb0fef1',
        ];

        yield 'BP512R1' => [
            new BP512R1(),
            [
                'crv' => 'BP-512',
                'd' => 'LGr6LUHaENZ-X1Q41afJJlEqW-NwWxDId7hUzCAfofZ4xocdqfsiD3wZmS61-h6meIRtUhP7VJb6u4bbjI5PAw',
                'x' => 'g2lV9LkARQroXX_b7np-_RzTdW1zfbO0HpPqKIW_U-5vic64bIEHTqlmzSMjvu2mwipMlu-hVUK5U5B2OPJQFQ',
                'y' => 'kmItRs7hNhruEiBnZSdsPM77fuUaHk15BUcxfWFp8ydSovpTNzGHwo5elNL3vvAn4BjVZvFilUs0XiL9nzNLqQ',
            ],
            '1a691318ac564e31613282e64d76734d510d0fbffb9142315fa163a6b9d3333e'
            . '31a61569a28023d03a3bd5c9c2eea32652d75a3d7c2444f230c026861c20fcce'
            . '0a328db6f5b9034a710a8a277ae50fc11841b74f98889133a13b6bbe6b9f31f2'
            . '08afa815daf81518e7140e3c43c872252114752f49f30bba1b79ac99d7c662db',
        ];
    }

    /**
     * @param array{crv: string, d: string, x: string, y: string} $key
     */
    private static function createKey(array $key): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => $key['crv'],
            'd' => $key['d'],
            'x' => $key['x'],
            'y' => $key['y'],
        ]);
    }
}

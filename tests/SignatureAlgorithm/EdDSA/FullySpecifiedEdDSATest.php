<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\EdDSA;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Exception\UnsupportedCurveException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\Ed25519;
use Jose\Component\Signature\Algorithm\Ed448;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function chr;
use function extension_loaded;
use function ord;
use function sprintf;
use function strlen;
use const PHP_VERSION_ID;

/**
 * The fully-specified "Ed25519" and "Ed448" algorithms of RFC 9864, next to the deprecated "EdDSA".
 *
 * @internal
 */
final class FullySpecifiedEdDSATest extends TestCase
{
    #[Test]
    public function theAlgorithmsAreNamedAsRegistered(): void
    {
        static::assertSame('Ed25519', (new Ed25519())->name());
        static::assertSame(['OKP'], (new Ed25519())->allowedKeyTypes());
        static::assertSame('EdDSA', (new EdDSA())->name());
        if (Ed448::isSupported()) {
            static::assertSame('Ed448', (new Ed448())->name());
            static::assertSame(['OKP'], (new Ed448())->allowedKeyTypes());
        }
    }

    #[Test]
    public function ed448IsGatedOnPhp84(): void
    {
        static::assertSame(PHP_VERSION_ID >= 80400 && extension_loaded('openssl'), Ed448::isSupported());
        static::assertSame(OKPKey::supportsOpenSSL(), Ed448::isSupported());
        if (Ed448::isSupported()) {
            static::assertInstanceOf(SignatureAlgorithm::class, new Ed448());

            return;
        }

        $this->expectException(MissingDependencyException::class);
        new Ed448();
    }

    /**
     * RFC 8037 appendix A.4: the key, the signing input and the signature.
     */
    #[Test]
    #[DataProvider('ed25519Algorithms')]
    public function theRfc8037VectorVerifiesUnderEdDSAAndEd25519(SignatureAlgorithm $algorithm): void
    {
        $key = self::rfc8037Key();
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64UrlSafe::decodeNoPadding(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
        );

        static::assertTrue($algorithm->verify($key, $input, $signature));
        static::assertSame($signature, $algorithm->sign($key, $input));
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function ed25519Algorithms(): iterable
    {
        yield 'EdDSA' => [new EdDSA()];
        yield 'Ed25519' => [new Ed25519()];
    }

    /**
     * RFC 8032 section 7.4, the first two vectors: the secret key, the public key, the message and the signature.
     *
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function rfc8032Ed448Vectors(): iterable
    {
        yield 'blank message' => [
            '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b',
            '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180',
            '',
            '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600',
        ];
        yield '1 octet' => [
            'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
            '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
            '03',
            '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00',
        ];
    }

    #[Test]
    #[DataProvider('rfc8032Ed448Vectors')]
    public function theRfc8032Ed448VectorsAreReproduced(string $d, string $x, string $message, string $signature): void
    {
        $this->requireEd448();
        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed448',
            'd' => Base64UrlSafe::encodeUnpadded(hex2bin($d)),
            'x' => Base64UrlSafe::encodeUnpadded(hex2bin($x)),
        ]);
        $algorithm = new Ed448();

        static::assertTrue($algorithm->verify($key, hex2bin($message), hex2bin($signature)));
        static::assertTrue($algorithm->verify($key->toPublic(), hex2bin($message), hex2bin($signature)));
        static::assertSame($signature, bin2hex($algorithm->sign($key, hex2bin($message))));
    }

    #[Test]
    public function aTruncatedOrTamperedEd448SignatureIsFalse(): void
    {
        $this->requireEd448();
        $key = (new JWKFactory())->okp('Ed448');
        $algorithm = new Ed448();
        $signature = $algorithm->sign($key, 'payload');
        static::assertSame(114, strlen($signature));

        $tampered = $signature;
        $tampered[10] = chr(ord($tampered[10]) ^ 0x01);

        static::assertFalse($algorithm->verify($key, 'payload', substr($signature, 0, 113)));
        static::assertFalse($algorithm->verify($key, 'payload', $signature . "\0"));
        static::assertFalse($algorithm->verify($key, 'payload', ''));
        static::assertFalse($algorithm->verify($key, 'payload', $tampered));
        static::assertFalse($algorithm->verify($key, 'other payload', $signature));
    }

    #[Test]
    public function aTruncatedOrTamperedEd25519SignatureIsFalse(): void
    {
        $key = self::rfc8037Key();
        $algorithm = new Ed25519();
        $signature = $algorithm->sign($key, 'payload');
        static::assertSame(64, strlen($signature));

        $tampered = $signature;
        $tampered[10] = chr(ord($tampered[10]) ^ 0x01);

        static::assertFalse($algorithm->verify($key, 'payload', substr($signature, 0, 63)));
        static::assertFalse($algorithm->verify($key, 'payload', ''));
        static::assertFalse($algorithm->verify($key, 'payload', $tampered));
    }

    #[Test]
    public function ed25519RefusesAnEd448Key(): void
    {
        $this->requireEd448();
        $key = (new JWKFactory())->okp('Ed448');

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The algorithm "Ed25519" only accepts keys on the "Ed25519" curve.');
        (new Ed25519())->sign($key, 'payload');
    }

    #[Test]
    public function ed448RefusesAnEd25519Key(): void
    {
        $this->requireEd448();

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The algorithm "Ed448" only accepts keys on the "Ed448" curve.');
        (new Ed448())->verify(self::rfc8037Key(), 'payload', str_repeat("\0", 114));
    }

    /**
     * The polymorphic algorithm keeps the exception it threw before 4.3 for a curve it does not handle.
     */
    #[Test]
    public function edDSAStillRefusesAnEd448Key(): void
    {
        $this->requireEd448();
        $key = (new JWKFactory())->okp('Ed448');

        $this->expectException(UnsupportedCurveException::class);
        $this->expectExceptionMessage('Unsupported curve.');
        (new EdDSA())->verify($key, 'payload', str_repeat("\0", 64));
    }

    #[Test]
    public function anX25519KeyIsRefused(): void
    {
        $key = (new JWKFactory())->okp('X25519');

        $this->expectException(InvalidKeyException::class);
        (new Ed25519())->sign($key, 'payload');
    }

    #[Test]
    public function aPublicKeyCannotSign(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The OKP key is not private');
        (new Ed25519())->sign(self::rfc8037Key()->toPublic(), 'payload');
    }

    #[Test]
    public function aKeyRestrictedToEdDSAIsRefusedByEd25519AndAcceptedByEdDSA(): void
    {
        $key = new JWK(self::rfc8037Key()->all() + [
            'alg' => 'EdDSA',
        ]);
        $edDSA = new AlgorithmManager([new EdDSA()]);

        $jws = (new JWSBuilder($edDSA))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'EdDSA',
            ])
            ->build();
        static::assertTrue((new JWSVerifier($edDSA))->verify($jws, $key, 0)->isVerified());

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The algorithm "Ed25519" is not allowed with this key.');
        (new JWSBuilder(new AlgorithmManager([new Ed25519()])))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'Ed25519',
            ]);
    }

    #[Test]
    public function aKeyRestrictedToEd25519IsRefusedByEdDSAAndAcceptedByEd25519(): void
    {
        $key = new JWK(self::rfc8037Key()->all() + [
            'alg' => 'Ed25519',
        ]);
        $ed25519 = new AlgorithmManager([new Ed25519()]);

        $jws = (new JWSBuilder($ed25519))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'Ed25519',
            ])
            ->build();
        static::assertTrue((new JWSVerifier($ed25519))->verify($jws, $key, 0)->isVerified());

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The algorithm "EdDSA" is not allowed with this key.');
        (new JWSBuilder(new AlgorithmManager([new EdDSA()])))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'EdDSA',
            ]);
    }

    #[Test]
    public function aTokenSignedWithEdDSAIsNotVerifiedByAVerifierKnowingEd25519Only(): void
    {
        $key = self::rfc8037Key();
        $jws = (new JWSBuilder(new AlgorithmManager([new EdDSA()])))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'EdDSA',
            ])
            ->build();

        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The algorithm "EdDSA" is not supported.');
        (new JWSVerifier(new AlgorithmManager([new Ed25519()])))->verify($jws, $key, 0);
    }

    /**
     * @return iterable<string, array{string, string, JWSSerializer}>
     */
    public static function roundTrips(): iterable
    {
        $serializers = [
            'compact' => new CompactSerializer(),
            'flattened' => new JSONFlattenedSerializer(),
            'general' => new JSONGeneralSerializer(),
        ];
        foreach (['Ed25519', 'Ed448'] as $algorithm) {
            foreach ($serializers as $name => $serializer) {
                yield sprintf('%s, %s', $algorithm, $name) => [$algorithm, $name, $serializer];
            }
        }
    }

    #[Test]
    #[DataProvider('roundTrips')]
    public function aTokenIsSignedAndVerifiedThroughEverySerializer(
        string $algorithmName,
        string $serializerName,
        JWSSerializer $serializer
    ): void {
        if ($algorithmName === 'Ed448') {
            $this->requireEd448();
        }
        $algorithm = $algorithmName === 'Ed448' ? new Ed448() : new Ed25519();
        $key = (new JWKFactory())->okp($algorithmName, [
            'kid' => 'key-' . $serializerName,
        ]);
        $manager = new AlgorithmManager([$algorithm]);

        $jws = (new JWSBuilder($manager))
            ->withPayload('{"iss":"me"}')
            ->addSignature($key, [
                'alg' => $algorithmName,
                'kid' => $key->get('kid'),
            ])
            ->build();
        $loaded = $serializer->unserialize($serializer->serialize($jws, 0));

        $result = (new JWSVerifier($manager))->verify($loaded, $key->toPublic(), 0);

        static::assertTrue($result->isVerified());
        static::assertSame('{"iss":"me"}', $loaded->getPayload());
        static::assertSame($algorithmName, $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
    }

    private function requireEd448(): void
    {
        if (! Ed448::isSupported()) {
            static::markTestSkipped('Ed448 needs ext-openssl on PHP 8.4 or later.');
        }
    }

    /**
     * The Ed25519 key of RFC 8037 appendix A.1.
     */
    private static function rfc8037Key(): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);
    }
}

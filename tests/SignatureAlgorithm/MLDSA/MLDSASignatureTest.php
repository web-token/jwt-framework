<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\MLDSA;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\MLDSA;
use Jose\Component\Signature\Algorithm\MLDSA44;
use Jose\Component\Signature\Algorithm\MLDSA65;
use Jose\Component\Signature\Algorithm\MLDSA87;
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
use function getenv;
use function ord;
use function sprintf;
use function strlen;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_VERSION_TEXT;
use const PHP_VERSION;
use const PHP_VERSION_ID;

/**
 * The ML-DSA algorithms of RFC 9964 over AKP keys.
 *
 * The platform gate is asserted first: on a platform without ML-DSA (PHP 8.2 or 8.3, or an OpenSSL runtime older
 * than 3.5) the algorithms report it through isSupported() and their constructor, and every other test of this
 * class is skipped. JOSE_ML_DSA_EXPECTED, set by the CI jobs, says which side of the gate a platform is expected to
 * be on, so that a runner drifting to another OpenSSL fails instead of silently losing the coverage.
 *
 * @internal
 */
final class MLDSASignatureTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<MLDSA>, string}>
     */
    public static function algorithms(): iterable
    {
        yield 'ML-DSA-44' => [MLDSA44::class, 'ML-DSA-44'];
        yield 'ML-DSA-65' => [MLDSA65::class, 'ML-DSA-65'];
        yield 'ML-DSA-87' => [MLDSA87::class, 'ML-DSA-87'];
    }

    #[Test]
    public function theThreeParameterSetsShareThePlatformGate(): void
    {
        static::assertSame(MLDSA44::isSupported(), MLDSA65::isSupported());
        static::assertSame(MLDSA44::isSupported(), MLDSA87::isSupported());
        static::assertSame(AKPKey::supportsOpenSSL(), MLDSA44::isSupported());
        if (PHP_VERSION_ID < 80400) {
            static::assertFalse(MLDSA44::isSupported(), 'PHP 8.3 and earlier cannot sign without a digest.');
        }
    }

    #[Test]
    public function thePlatformIsOnTheExpectedSideOfTheGate(): void
    {
        $expected = getenv('JOSE_ML_DSA_EXPECTED');
        if ($expected === false || $expected === '') {
            static::markTestSkipped('JOSE_ML_DSA_EXPECTED is not set: the platform is taken as it comes.');
        }
        static::assertContains($expected, ['yes', 'no'], 'JOSE_ML_DSA_EXPECTED must be "yes" or "no".');
        static::assertSame($expected === 'yes', MLDSA44::isSupported(), sprintf(
            'ML-DSA was expected to be %s on PHP %s built against %s.',
            $expected === 'yes' ? 'available' : 'unavailable',
            PHP_VERSION,
            OPENSSL_VERSION_TEXT
        ));
    }

    /**
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function theAlgorithmIsNamedAsRegistered(string $class, string $name): void
    {
        $this->requireMLDSA();
        $algorithm = new $class();

        static::assertSame($name, $algorithm->name());
        static::assertSame(['AKP'], $algorithm->allowedKeyTypes());
    }

    /**
     * @param class-string<MLDSA> $class
     */
    #[Test]
    #[DataProvider('algorithms')]
    public function theConstructorThrowsWhereThePlatformHasNoMLDSA(string $class, string $name): void
    {
        if ($class::isSupported()) {
            static::markTestSkipped('This platform has ML-DSA.');
        }

        $this->expectException(MissingDependencyException::class);
        $this->expectExceptionMessage(sprintf('The algorithm "%s" requires', $name));
        new $class();
    }

    /**
     * RFC 9964 appendix A.1: the JWS of each parameter set verifies with the JWK the RFC prints, the all-zero seed
     * expands to the printed public key, and the "kid" of the JWK is its thumbprint.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function rfc9964Examples(): iterable
    {
        $examples = json_decode(
            (string) file_get_contents(__DIR__ . '/../../fixtures/rfc9964/appendix-a.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($examples as $example) {
            yield $example['jwk']['alg'] => [$example];
        }
    }

    /**
     * @param array<string, mixed> $example
     */
    #[Test]
    #[DataProvider('rfc9964Examples')]
    public function theRfc9964ExampleVerifies(array $example): void
    {
        $this->requireMLDSA();
        $key = new JWK($example['jwk']);
        $algorithm = self::algorithmNamed($example['jwk']['alg']);
        $input = hex2bin($example['raw_to_be_signed']);
        $signature = hex2bin($example['raw_signature']);

        static::assertTrue($algorithm->verify($key, $input, $signature));
        static::assertTrue($algorithm->verify($key->toPublic(), $input, $signature));
        static::assertSame(hex2bin($example['raw_public_key']), Base64UrlSafe::decodeNoPadding($key->getString('pub')));
        static::assertSame(
            hex2bin($example['raw_public_key']),
            AKPKey::publicKeyFromSeed($example['jwk']['alg'], hex2bin($example['priv']))
        );
        static::assertSame($example['jwk']['kid'], $key->thumbprint('sha256'));
    }

    /**
     * @param array<string, mixed> $example
     */
    #[Test]
    #[DataProvider('rfc9964Examples')]
    public function theRfc9964JwsIsLoadedAndVerified(array $example): void
    {
        $this->requireMLDSA();
        $key = new JWK($example['jwk']);
        $jws = (new CompactSerializer())->unserialize($example['jws']);
        $verifier = new JWSVerifier(new AlgorithmManager([new MLDSA44(), new MLDSA65(), new MLDSA87()]));

        $result = $verifier->verify($jws, $key->toPublic(), 0);

        static::assertTrue($result->isVerified());
        static::assertSame($example['jwk']['alg'], $jws->getSignature(0)->getProtectedHeaderParameter('alg'));
    }

    /**
     * ML-DSA is randomized by default (FIPS 204 algorithm 2 draws rnd), so a signature is not reproduced; it verifies.
     *
     * @param array<string, mixed> $example
     */
    #[Test]
    #[DataProvider('rfc9964Examples')]
    public function theRfc9964KeySignsAgain(array $example): void
    {
        $this->requireMLDSA();
        $key = new JWK($example['jwk']);
        $algorithm = self::algorithmNamed($example['jwk']['alg']);
        $input = hex2bin($example['raw_to_be_signed']);

        $signature = $algorithm->sign($key, $input);

        static::assertSame(AKPKey::SIGNATURE_LENGTHS[$example['jwk']['alg']], strlen($signature));
        static::assertTrue($algorithm->verify($key->toPublic(), $input, $signature));
    }

    /**
     * NIST ACVP ML-DSA-keyGen-FIPS204: the seed and the public key it expands to.
     *
     * @return iterable<string, array{string, string, string}>
     */
    public static function nistKeyGenCases(): iterable
    {
        $file = json_decode(
            (string) file_get_contents(__DIR__ . '/../../fixtures/nist-acvp/ml-dsa/keygen.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($file['testGroups'] as $group) {
            foreach ($group['tests'] as $case) {
                yield sprintf('%s, tcId %s', $group['parameterSet'], $case['tcId']) => [
                    $group['parameterSet'],
                    $case['seed'],
                    $case['pk'],
                ];
            }
        }
    }

    #[Test]
    #[DataProvider('nistKeyGenCases')]
    public function theNistSeedExpandsToTheNistPublicKey(string $algorithm, string $seed, string $pk): void
    {
        $this->requireMLDSA();

        static::assertSame(strtolower($pk), bin2hex(AKPKey::publicKeyFromSeed($algorithm, hex2bin($seed))));
    }

    /**
     * NIST ACVP ML-DSA-sigGen-FIPS204, the pure-mode cases with an empty context.
     *
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function nistSigGenCases(): iterable
    {
        $file = json_decode(
            (string) file_get_contents(__DIR__ . '/../../fixtures/nist-acvp/ml-dsa/siggen.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($file['testGroups'] as $group) {
            foreach ($group['tests'] as $case) {
                yield sprintf('%s, tgId %s, tcId %s', $group['parameterSet'], $group['tgId'], $case['tcId']) => [
                    $group['parameterSet'],
                    $case['pk'],
                    $case['message'],
                    $case['signature'],
                ];
            }
        }
    }

    #[Test]
    #[DataProvider('nistSigGenCases')]
    public function theNistSignatureVerifies(string $algorithm, string $pk, string $message, string $signature): void
    {
        $this->requireMLDSA();
        $key = new JWK([
            'kty' => 'AKP',
            'alg' => $algorithm,
            'pub' => Base64UrlSafe::encodeUnpadded(hex2bin($pk)),
        ]);

        static::assertTrue(self::algorithmNamed($algorithm)->verify($key, hex2bin($message), hex2bin($signature)));
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
        foreach (['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as $algorithm) {
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
        $this->requireMLDSA();
        $algorithm = self::algorithmNamed($algorithmName);
        $key = (new JWKFactory())->mldsa($algorithmName, [
            'kid' => 'key-' . $serializerName,
            'use' => 'sig',
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

    #[Test]
    public function aTruncatedOrTamperedSignatureIsFalse(): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->mldsa('ML-DSA-44');
        $algorithm = new MLDSA44();
        $signature = $algorithm->sign($key, 'payload');
        static::assertSame(2420, strlen($signature));

        $tampered = $signature;
        $tampered[100] = chr(ord($tampered[100]) ^ 0x01);

        static::assertFalse($algorithm->verify($key, 'payload', substr($signature, 0, 2419)));
        static::assertFalse($algorithm->verify($key, 'payload', $signature . "\0"));
        static::assertFalse($algorithm->verify($key, 'payload', ''));
        static::assertFalse($algorithm->verify($key, 'payload', $tampered));
        static::assertFalse($algorithm->verify($key, 'other payload', $signature));
    }

    #[Test]
    public function aPublicKeyCannotSign(): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->mldsa('ML-DSA-44')
            ->toPublic();
        static::assertFalse($key->has('priv'));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The AKP key is not private');
        (new MLDSA44())->sign($key, 'payload');
    }

    /**
     * The keys refused before any OpenSSL call (RFC 9964 section 7.3): the check runs on a platform without
     * ML-DSA too, up to the point where the seed would have to be expanded.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function malformedKeys(): iterable
    {
        $pub = Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 1312));
        Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 32));

        yield 'wrong key type' => [[
            'kty' => 'OKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub,
        ], 'Wrong key type.'];
        yield 'missing alg' => [[
            'kty' => 'AKP',
            'pub' => $pub,
        ], 'The AKP key carries no "alg" parameter'];
        yield 'alg of another parameter set' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-65',
            'pub' => $pub,
        ], 'The AKP key belongs to the algorithm "ML-DSA-65" and cannot be used with "ML-DSA-44".'];
        yield 'alg of another family' => [[
            'kty' => 'AKP',
            'alg' => 'EdDSA',
            'pub' => $pub,
        ], 'The AKP key belongs to the algorithm "EdDSA" and cannot be used with "ML-DSA-44".'];
        yield 'missing pub' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
        ], 'The "pub" parameter is missing or not a string.'];
        yield 'pub of the wrong length' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 1952)),
        ], 'The "pub" parameter of an ML-DSA-44 key must be 1312 bytes long.'];
        yield 'priv that is not the seed' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub,
            'priv' => Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 2560)),
        ], 'The "priv" parameter of an ML-DSA key must be the 32-byte seed.'];
        yield 'priv of 31 bytes' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub,
            'priv' => Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 31)),
        ], 'The "priv" parameter of an ML-DSA key must be the 32-byte seed.'];
        yield 'priv not a string' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub,
            'priv' => 42,
        ], 'The "priv" parameter is missing or not a string.'];
    }

    /**
     * @param array<string, mixed> $values
     */
    #[Test]
    #[DataProvider('malformedKeys')]
    public function aMalformedKeyIsRejectedBeforeOpenSSLIsCalled(array $values, string $message): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage($message);

        AKPKey::checkKey(new JWK($values), 'ML-DSA-44');
    }

    #[Test]
    public function aMalformedKeyIsRejectedByTheAlgorithm(): void
    {
        $this->requireMLDSA();
        $key = new JWK([
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 1312)),
            'priv' => Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 2560)),
        ]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The "priv" parameter of an ML-DSA key must be the 32-byte seed.');
        (new MLDSA44())->verify($key, 'payload', str_repeat("\0", 2420));
    }

    #[Test]
    public function aPublicKeyThatDoesNotMatchTheSeedIsRejected(): void
    {
        $this->requireMLDSA();
        $genuine = (new JWKFactory())->mldsa('ML-DSA-44');
        $other = (new JWKFactory())->mldsa('ML-DSA-44');
        $mismatched = new JWK([
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $other->get('pub'),
            'priv' => $genuine->get('priv'),
        ]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The "pub" parameter is not the public key the "priv" seed expands to.');
        (new MLDSA44())->sign($mismatched, 'payload');
    }

    #[Test]
    public function aKeyOfAnotherParameterSetIsRefusedByTheBuilder(): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->mldsa('ML-DSA-65');

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The algorithm "ML-DSA-44" is not allowed with this key.');
        (new JWSBuilder(new AlgorithmManager([new MLDSA44()])))
            ->withPayload('payload')
            ->addSignature($key, [
                'alg' => 'ML-DSA-44',
            ]);
    }

    private function requireMLDSA(): void
    {
        if (! MLDSA44::isSupported()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
    }

    private static function algorithmNamed(string $name): MLDSA
    {
        return match ($name) {
            'ML-DSA-44' => new MLDSA44(),
            'ML-DSA-65' => new MLDSA65(),
            default => new MLDSA87(),
        };
    }
}

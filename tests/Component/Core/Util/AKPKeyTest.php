<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\ObjectIdentifier;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use function chr;
use function strlen;
use const JSON_THROW_ON_ERROR;
use const PHP_VERSION_ID;

/**
 * The OpenSSL plumbing of the AKP keys: the PEM forms of RFC 9881, key generation and PEM loading.
 *
 * @internal
 */
final class AKPKeyTest extends TestCase
{
    #[Test]
    public function theGateNeedsPhp84AndAnOpenSSLRuntimeProvidingMLDSA(): void
    {
        static::assertSame(PHP_VERSION_ID >= 80400 && AKPKey::isProvidedByOpenSSL(), AKPKey::supportsOpenSSL());
        static::assertSame(AKPKey::isProvidedByOpenSSL(), AKPKey::isProvidedByOpenSSL());
        if (PHP_VERSION_ID < 80400) {
            static::assertStringContainsString('PHP 8.4', AKPKey::missingDependency());
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function openSSLVectors(): iterable
    {
        $vectors = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../fixtures/rfc9964/openssl-cli/vectors.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($vectors as $vector) {
            yield $vector['algorithm'] => [$vector];
        }
    }

    /**
     * A public key PEM is loaded without OpenSSL: the SubjectPublicKeyInfo is read as such.
     *
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('openSSLVectors')]
    public function aPublicKeyPemIsLoadedOnEveryPlatform(array $vector): void
    {
        static::assertTrue(AKPKey::isMLDSAPEM($vector['public_key_pem']));

        $values = AKPKey::loadFromPEM($vector['public_key_pem']);

        static::assertSame([
            'kty' => 'AKP',
            'alg' => $vector['algorithm'],
            'pub' => Base64UrlSafe::encodeUnpadded(hex2bin($vector['pub_hex'])),
        ], $values);
        static::assertSame(trim($vector['public_key_pem']), trim(AKPKey::convertPublicKeyToPEM(new JWK($values))));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('openSSLVectors')]
    public function aSeedOnlyPrivateKeyPemIsLoadedAndWrittenBack(array $vector): void
    {
        $this->requireMLDSA();
        static::assertTrue(AKPKey::isMLDSAPEM($vector['private_key_pem']));

        $values = AKPKey::loadFromPEM($vector['private_key_pem']);

        static::assertSame([
            'kty' => 'AKP',
            'alg' => $vector['algorithm'],
            'pub' => Base64UrlSafe::encodeUnpadded(hex2bin($vector['pub_hex'])),
            'priv' => Base64UrlSafe::encodeUnpadded(hex2bin($vector['seed_hex'])),
        ], $values);
        $key = new JWK($values);
        static::assertSame(trim($vector['private_key_pem']), trim(AKPKey::convertPrivateKeyToPKCS8PEM($key)));
        static::assertSame(trim($vector['private_key_pem']), trim(AKPKey::convertToPKCS8PEM($key)));
        static::assertSame(trim($vector['public_key_pem']), trim(AKPKey::convertToPKCS8PEM($key->toPublic())));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('openSSLVectors')]
    public function theOpenSSLCommandLineSignatureVerifies(array $vector): void
    {
        $this->requireMLDSA();
        $key = new JWK(AKPKey::loadFromPEM($vector['public_key_pem']));

        static::assertTrue(AKPKey::verify($key, $vector['message'], hex2bin($vector['signature_hex'])));
        static::assertFalse(AKPKey::verify($key, $vector['message'] . 'x', hex2bin($vector['signature_hex'])));
    }

    /**
     * The "both" choice of the ML-DSA-PrivateKey of RFC 9881 carries the seed next to the expanded key: the seed is
     * taken, the expanded key ignored.
     */
    #[Test]
    public function aBothFormPrivateKeyPemGivesItsSeed(): void
    {
        $this->requireMLDSA();
        $seed = str_repeat("\x07", 32);
        $expanded = str_repeat("\x08", 2560);
        $both = "\xa2" . self::derLength(2 + 32 + 4 + 2560) . "\x04\x20" . $seed . "\x04\x82\x0a\x00" . $expanded;
        $pem = self::privateKeyPem('2.16.840.1.101.3.4.3.17', $both);

        $values = AKPKey::loadFromPEM($pem);

        static::assertSame(Base64UrlSafe::encodeUnpadded($seed), $values['priv']);
        static::assertSame(
            Base64UrlSafe::encodeUnpadded(AKPKey::publicKeyFromSeed('ML-DSA-44', $seed)),
            $values['pub']
        );
    }

    #[Test]
    public function anExpandedKeyOnlyPrivateKeyPemIsRefused(): void
    {
        $expanded = "\x81\x82\x0a\x00" . str_repeat("\x08", 2560);
        $pem = self::privateKeyPem('2.16.840.1.101.3.4.3.17', $expanded);
        static::assertTrue(AKPKey::isMLDSAPEM($pem));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('not represented by its seed');
        AKPKey::loadFromPEM($pem);
    }

    #[Test]
    public function aSeedOfTheWrongLengthInAPemIsRefused(): void
    {
        $pem = self::privateKeyPem('2.16.840.1.101.3.4.3.17', "\x80\x1f" . str_repeat("\x07", 31));

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The seed of an ML-DSA key must be 32 bytes long.');
        AKPKey::loadFromPEM($pem);
    }

    #[Test]
    public function aPemOfAnotherAlgorithmIsNotAnMLDSAPem(): void
    {
        $ed25519 = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";

        static::assertFalse(AKPKey::isMLDSAPEM($ed25519));
        static::assertFalse(AKPKey::isMLDSAPEM('not a PEM'));

        $this->expectException(UnsupportedAlgorithmException::class);
        AKPKey::loadFromPEM($ed25519);
    }

    #[Test]
    public function aKeyIsGeneratedFromARandomOrAGivenSeed(): void
    {
        $this->requireMLDSA();
        $random = AKPKey::generate('ML-DSA-65');
        static::assertSame('AKP', $random->get('kty'));
        static::assertSame('ML-DSA-65', $random->get('alg'));
        static::assertSame(1952, strlen(Base64UrlSafe::decodeNoPadding($random->getString('pub'))));
        static::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($random->getString('priv'))));

        $seed = Base64UrlSafe::decodeNoPadding($random->getString('priv'));
        $rebuilt = AKPKey::generate('ML-DSA-65', $seed);
        static::assertSame($random->all(), $rebuilt->all());
        static::assertNotSame($random->get('priv'), AKPKey::generate('ML-DSA-65')->get('priv'));
    }

    #[Test]
    public function aSeedOfTheWrongLengthCannotGenerateAKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The seed of an ML-DSA key must be 32 bytes long.');

        AKPKey::generate('ML-DSA-44', str_repeat("\0", 31));
    }

    #[Test]
    public function anUnknownParameterSetCannotGenerateAKey(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        $this->expectExceptionMessage('The algorithm "ML-DSA-128" is not an ML-DSA algorithm.');

        AKPKey::generate('ML-DSA-128');
    }

    #[Test]
    public function aKeyWithoutAlgHasNoPemForm(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The AKP key carries no "alg" parameter');

        AKPKey::convertPublicKeyToPEM(new JWK([
            'kty' => 'AKP',
            'pub' => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 1312)),
        ]));
    }

    private function requireMLDSA(): void
    {
        if (! AKPKey::supportsOpenSSL()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
    }

    private static function privateKeyPem(string $oid, string $privateKeyContent): string
    {
        $der = Sequence::create(
            Integer::create(0),
            Sequence::create(
                ObjectIdentifier::create($oid)
            ),
            OctetString::create($privateKeyContent)
        )->toDER();

        return "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PRIVATE KEY-----\n";
    }

    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\0");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}

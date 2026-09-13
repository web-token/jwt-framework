<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use const JSON_THROW_ON_ERROR;

/**
 * The AKP keys of RFC 9964 through JWK, the key factory and the key converter.
 *
 * @internal
 */
final class AKPKeysTest extends TestCase
{
    /**
     * RFC 9964 appendix A.1: the "kid" of every JWK is the thumbprint of section 6 over "alg", "kty" and "pub".
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function rfc9964Keys(): iterable
    {
        $examples = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../fixtures/rfc9964/appendix-a.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        foreach ($examples as $example) {
            yield $example['jwk']['alg'] => [$example['jwk']];
        }
    }

    /**
     * @param array<string, mixed> $values
     */
    #[Test]
    #[DataProvider('rfc9964Keys')]
    public function theThumbprintIsTheKidOfTheRfc(array $values): void
    {
        $key = new JWK($values);

        static::assertSame($values['kid'], $key->thumbprint('sha256'));
        static::assertSame($values['kid'], $key->toPublic()->thumbprint('sha256'));
        static::assertSame(
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' . $values['kid'],
            $key->thumbprintUri()
        );
    }

    #[Test]
    public function theThumbprintOfAnAkpKeyRequiresAlg(): void
    {
        $key = new JWK([
            'kty' => 'AKP',
            'pub' => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 1312)),
        ]);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Unable to compute the thumbprint of an AKP key without "alg"');
        $key->thumbprint('sha256');
    }

    /**
     * @param array<string, mixed> $values
     */
    #[Test]
    #[DataProvider('rfc9964Keys')]
    public function toPublicStripsTheSeed(array $values): void
    {
        $public = (new JWK($values))->toPublic();

        static::assertFalse($public->has('priv'));
        static::assertSame(['kid', 'kty', 'alg', 'pub'], array_keys($public->all()));
        static::assertSame($public->all(), $public->toPublic()->all());
    }

    #[Test]
    public function theFactoryGeneratesAKeyFromARandomSeed(): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->mldsa('ML-DSA-87', [
            'kid' => 'KEY',
            'use' => 'sig',
        ]);

        static::assertSame('AKP', $key->get('kty'));
        static::assertSame('ML-DSA-87', $key->get('alg'));
        static::assertSame('KEY', $key->get('kid'));
        static::assertSame('sig', $key->get('use'));
        static::assertSame(2592, strlen(Base64UrlSafe::decodeNoPadding($key->getString('pub'))));
        static::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($key->getString('priv'))));
    }

    /**
     * @param array<string, mixed> $values
     */
    #[Test]
    #[DataProvider('rfc9964Keys')]
    public function theFactoryRebuildsAKeyFromItsStoredSeed(array $values): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->mldsa($values['alg'], [
            'priv' => $values['priv'],
            'kid' => $values['kid'],
        ]);

        static::assertSame($values['pub'], $key->get('pub'));
        static::assertSame($values['kid'], $key->thumbprint('sha256'));
    }

    #[Test]
    public function theFactoryRefusesASeedThatIsNotAString(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('The "priv" parameter must be the base64url encoded seed.');

        (new JWKFactory())->mldsa('ML-DSA-44', [
            'priv' => 42,
        ]);
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
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('openSSLVectors')]
    public function thePublicKeyPemIsLoadedByTheFactory(array $vector): void
    {
        $key = (new JWKFactory())->fromKey($vector['public_key_pem'], null, [
            'use' => 'sig',
        ]);

        static::assertSame('AKP', $key->get('kty'));
        static::assertSame($vector['algorithm'], $key->get('alg'));
        static::assertSame(Base64UrlSafe::encodeUnpadded(hex2bin($vector['pub_hex'])), $key->get('pub'));
        static::assertFalse($key->has('priv'));
        static::assertSame('sig', $key->get('use'));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[Test]
    #[DataProvider('openSSLVectors')]
    public function theSeedOnlyPrivateKeyPemIsLoadedByTheFactory(array $vector): void
    {
        $this->requireMLDSA();
        $key = (new JWKFactory())->fromKey($vector['private_key_pem']);

        static::assertSame($vector['algorithm'], $key->get('alg'));
        static::assertSame(Base64UrlSafe::encodeUnpadded(hex2bin($vector['pub_hex'])), $key->get('pub'));
        static::assertSame(Base64UrlSafe::encodeUnpadded(hex2bin($vector['seed_hex'])), $key->get('priv'));
    }

    /**
     * A certificate holding an ML-DSA-44 key, issued by a P-256 CA: the public key is loaded whatever the OpenSSL
     * runtime, and the certificate parameters are set as for any other certificate.
     */
    #[Test]
    public function aCertificateHoldingAnMLDSAKeyIsLoadedByTheFactory(): void
    {
        $certificate = (string) file_get_contents(__DIR__ . '/../../../fixtures/rfc9964/openssl-cli/ml-dsa-44-certificate.pem');
        $vectors = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../fixtures/rfc9964/openssl-cli/vectors.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        $key = (new JWKFactory())->fromCertificate($certificate);

        static::assertSame('AKP', $key->get('kty'));
        static::assertSame('ML-DSA-44', $key->get('alg'));
        static::assertSame(Base64UrlSafe::encodeUnpadded(hex2bin($vectors[0]['pub_hex'])), $key->get('pub'));
        static::assertFalse($key->has('priv'));
        static::assertTrue($key->has('x5c'));
        static::assertTrue($key->has('x5t'));
        static::assertTrue($key->has('x5t#256'));
    }

    private function requireMLDSA(): void
    {
        if (! AKPKey::supportsOpenSSL()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
    }
}

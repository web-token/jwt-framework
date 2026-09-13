<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function strlen;

/**
 * ECDH-ES with X448 keys (RFC 8037 section 3.2), through OpenSSL.
 *
 * @internal
 */
final class ECDHESWithX448EncryptionTest extends EncryptionTestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function keyAgreementAlgorithms(): iterable
    {
        yield 'ECDH-ES, A256GCM' => ['ECDH-ES', 'A256GCM'];
        yield 'ECDH-ES+A128KW, A128GCM' => ['ECDH-ES+A128KW', 'A128GCM'];
        yield 'ECDH-ES+A256KW, A256CBC-HS512' => ['ECDH-ES+A256KW', 'A256CBC-HS512'];
    }

    #[Test]
    #[DataProvider('keyAgreementAlgorithms')]
    public function anEphemeralStaticAgreementRoundTripsWithX448(string $alg, string $enc): void
    {
        $this->requireX448();
        $receiverKey = self::receiverKey();
        $input = 'The quick brown fox jumps over the lazy dog.';

        $jwe = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->withPayload($input)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->addRecipient($receiverKey->toPublic())
            ->build();
        $serializerManager = $this->getJWESerializerManager();
        $loaded = $serializerManager->unserialize($serializerManager->serialize('jwe_compact', $jwe, 0));

        $epk = $loaded->getSharedProtectedHeaderParameter('epk');
        static::assertIsArray($epk);
        static::assertSame('OKP', $epk['kty']);
        static::assertSame('X448', $epk['crv']);
        static::assertArrayNotHasKey('d', $epk);
        static::assertSame(56, strlen(Base64UrlSafe::decodeNoPadding($epk['x'])));

        $result = $this->getJWEDecrypterFactory()
            ->create([$alg, $enc])
            ->decrypt($loaded, $receiverKey, 0);
        static::assertTrue($result->isDecrypted());
        static::assertSame($input, $result->getJwe()->getPayload());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function staticStaticAlgorithms(): iterable
    {
        yield 'ECDH-SS, A256GCM' => ['ECDH-SS', 'A256GCM'];
        yield 'ECDH-SS+A256KW, A128CBC-HS256' => ['ECDH-SS+A256KW', 'A128CBC-HS256'];
    }

    #[Test]
    #[DataProvider('staticStaticAlgorithms')]
    public function aStaticStaticAgreementRoundTripsWithX448(string $alg, string $enc): void
    {
        $this->requireX448();
        $receiverKey = self::receiverKey();
        $senderKey = OKPKey::generate('X448');
        $input = 'The quick brown fox jumps over the lazy dog.';

        $jwe = $this->getJWEBuilderFactory()
            ->create([$alg, $enc])
            ->withPayload($input)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => $enc,
            ])
            ->withSenderKey($senderKey)
            ->addRecipient($receiverKey->toPublic())
            ->build();
        $serializerManager = $this->getJWESerializerManager();
        $loaded = $serializerManager->unserialize($serializerManager->serialize('jwe_json_flattened', $jwe, 0));

        static::assertFalse($loaded->hasSharedProtectedHeaderParameter('epk'));
        $result = $this->getJWEDecrypterFactory()
            ->create([$alg, $enc])
            ->decrypt($loaded, $senderKey->toPublic(), 0, $receiverKey);
        static::assertTrue($result->isDecrypted());
        static::assertSame($input, $result->getJwe()->getPayload());
    }

    /**
     * RFC 7748 section 6.2: with Alice's key as the ephemeral one and Bob's as the recipient's, the agreement key is
     * the shared secret K of the RFC.
     */
    #[Test]
    public function theAgreementKeyIsTheRfc7748SharedSecret(): void
    {
        $this->requireX448();
        $alice = new JWK([
            'kty' => 'OKP',
            'crv' => 'X448',
            'x' => Base64UrlSafe::encodeUnpadded(hex2bin(
                '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0'
            )),
            'd' => Base64UrlSafe::encodeUnpadded(hex2bin(
                '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b'
            )),
        ]);
        $bob = new JWK([
            'kty' => 'OKP',
            'crv' => 'X448',
            'x' => Base64UrlSafe::encodeUnpadded(hex2bin(
                '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609'
            )),
            'd' => Base64UrlSafe::encodeUnpadded(hex2bin(
                '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d'
            )),
        ]);
        $algorithm = new ECDHES();

        $additionalHeader = [];
        $fromSender = $algorithm->getAgreementKey(256, 'A256GCM', $bob->toPublic(), $alice, [], $additionalHeader);
        static::assertSame($alice->toPublic()->all(), $additionalHeader['epk']);
        $fromRecipient = $algorithm->getAgreementKey(256, 'A256GCM', $bob, null, [
            'epk' => $additionalHeader['epk'],
        ]);

        static::assertSame($fromSender, $fromRecipient);
        static::assertSame(
            hash('sha256', "\0\0\0\1" . hex2bin(
                '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d'
            ) . "\0\0\0\x07A256GCM\0\0\0\0\0\0\0\0\0\0\1\0", true),
            $fromSender
        );
    }

    #[Test]
    public function anX448RecipientCannotUseAnX25519EphemeralKey(): void
    {
        $this->requireX448();
        $receiverKey = self::receiverKey();
        $epk = OKPKey::generate('X25519')->toPublic();

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Curves are different');
        (new ECDHES())->getAgreementKey(256, 'A256GCM', $receiverKey, null, [
            'epk' => $epk->all(),
        ]);
    }

    private function requireX448(): void
    {
        if (! OKPKey::isCurveSupported('X448')) {
            static::markTestSkipped('X448 needs ext-openssl on PHP 8.4 or later.');
        }
    }

    private static function receiverKey(): JWK
    {
        return OKPKey::generate('X448');
    }
}

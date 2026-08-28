<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use LogicException;
use PHPUnit\Framework\Attributes\Test;

/**
 * Class JWEBuilderSenderKeyTest.
 *
 * The static key agreement algorithms derive the agreement key from the two static keys. On the decryption
 * side the roles are swapped: the public key of the sender is the key of the key set and the private key of
 * the recipient is the sender key, as the "epk" header parameter is not part of the token.
 *
 * @internal
 */
final class JWEBuilderSenderKeyTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    #[Test]
    public function theSenderKeyCanBeSetBeforeTheRecipient(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-SS', 'A128CBC-HS256']);

        $jwe = $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS',
                'enc' => 'A128CBC-HS256',
            ])
            ->withSenderKey($this->getSenderKey())
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->build();

        static::assertFalse($jwe->hasSharedProtectedHeaderParameter('epk'));
        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, ['ECDH-SS', 'A128CBC-HS256']));
    }

    #[Test]
    public function theSenderKeyCanBeSetAfterTheRecipient(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-SS', 'A128CBC-HS256']);

        $jwe = $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS',
                'enc' => 'A128CBC-HS256',
            ])
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->withSenderKey($this->getSenderKey())
            ->build();

        static::assertFalse($jwe->hasSharedProtectedHeaderParameter('epk'));
        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, ['ECDH-SS', 'A128CBC-HS256']));
    }

    #[Test]
    public function aDirectStaticKeyAgreementRequiresASenderKey(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-SS', 'A128CBC-HS256']);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The sender key shall be set');

        $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS',
                'enc' => 'A128CBC-HS256',
            ])
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->build();
    }

    #[Test]
    public function theSenderKeyIsUsedWithAStaticKeyAgreementWithKeyWrapping(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-SS+A128KW', 'A128CBC-HS256']);

        $jwe = $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS+A128KW',
                'enc' => 'A128CBC-HS256',
            ])
            ->withSenderKey($this->getSenderKey())
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->build();

        static::assertFalse($jwe->hasSharedProtectedHeaderParameter('epk'));
        static::assertSame(self::PAYLOAD, $this->decrypt($jwe, ['ECDH-SS+A128KW', 'A128CBC-HS256']));
    }

    #[Test]
    public function theSenderKeyReplacesTheEphemeralKeyOfAnEphemeralStaticKeyAgreement(): void
    {
        $senderKey = $this->getSenderKey();
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-ES', 'A128CBC-HS256']);

        $jwe = $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-ES',
                'enc' => 'A128CBC-HS256',
            ])
            ->withSenderKey($senderKey)
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->build();

        static::assertSame($senderKey->toPublic()->all(), $jwe->getSharedProtectedHeaderParameter('epk'));

        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['ECDH-ES', 'A128CBC-HS256']);
        $loaded = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_compact', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded, $this->getRecipientKey(), 0));
        static::assertSame(self::PAYLOAD, $loaded->getPayload());
    }

    #[Test]
    public function theSenderKeyIsVerifiedWhenTheTokenIsBuilt(): void
    {
        $senderKey = new JWK($this->getSenderKey()->all() + [
            'use' => 'sig',
        ]);
        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['ECDH-SS', 'A128CBC-HS256']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key cannot be used to encrypt or decrypt.');

        $jweBuilder
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS',
                'enc' => 'A128CBC-HS256',
            ])
            ->withSenderKey($senderKey)
            ->addRecipient($this->getRecipientKey()->toPublic())
            ->build();
    }

    /**
     * @param array<string> $algorithms
     */
    private function decrypt(JWE $jwe, array $algorithms): ?string
    {
        $serializerManager = $this->getJWESerializerManager();
        $loaded = $serializerManager->unserialize($serializerManager->serialize('jwe_compact', $jwe, 0));
        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create($algorithms);
        static::assertTrue(
            $jweDecrypter->decryptUsingKey($loaded, $this->getSenderKey()->toPublic(), 0, $this->getRecipientKey())
        );

        return $loaded->getPayload();
    }

    private function getSenderKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
        ]);
    }

    private function getRecipientKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
    }
}

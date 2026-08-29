<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\Attributes\Test;

/**
 * The shared protected header, the shared unprotected header and the per-recipient header must be disjoint:
 * an unprotected header parameter is never allowed to redefine an integrity protected one, otherwise the
 * header checkers and the decryption process may not use the same values.
 *
 * In addition, "enc" is only read from the protected header and "alg" only from the protected header or the
 * per-recipient header (RFC 7516 section 7.2.1). The shared unprotected header is never a valid source for
 * those two parameters.
 *
 * @internal
 */
final class HeaderParameterConfusionTest extends EncryptionTestCase
{
    #[Test]
    public function theKeyEncryptionAlgorithmCannotBeOverriddenByARecipientHeader(): void
    {
        $token = $this->createFlattenedToken();
        $token['header'] = [
            'alg' => 'dir',
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: alg.');

        $this->decrypt($token);
    }

    #[Test]
    public function theKeyEncryptionAlgorithmCannotBeOverriddenByTheSharedUnprotectedHeader(): void
    {
        $token = $this->createFlattenedToken();
        $token['unprotected'] = [
            'alg' => 'dir',
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: alg.');

        $this->decrypt($token);
    }

    #[Test]
    public function theContentEncryptionAlgorithmCannotBeOverriddenByAnUnprotectedHeader(): void
    {
        $token = $this->createFlattenedToken();
        $token['unprotected'] = [
            'enc' => 'A256GCM',
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: enc.');

        $this->decrypt($token);
    }

    #[Test]
    public function theContentEncryptionAlgorithmCannotBeOverriddenByARecipientHeader(): void
    {
        $token = $this->createFlattenedToken();
        $token['header'] = [
            'enc' => 'A256GCM',
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: enc.');

        $this->decrypt($token);
    }

    #[Test]
    public function aNonStringAlgorithmIsRejected(): void
    {
        $token = $this->createFlattenedToken();
        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding($token['protected']));
        $protectedHeader['alg'] = ['A128KW'];
        $token['protected'] = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($protectedHeader));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The "alg" parameter must be a non-empty string set in the protected header or in the recipient header.'
        );

        $this->decrypt($token);
    }

    #[Test]
    public function theKeyEncryptionAlgorithmCannotComeFromTheSharedUnprotectedHeader(): void
    {
        $token = $this->createFlattenedToken();
        $alg = $this->moveOutOfTheProtectedHeader($token, 'alg');
        $token['unprotected'] = [
            'alg' => $alg,
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The "alg" parameter must be a non-empty string set in the protected header or in the recipient header.'
        );

        $this->decrypt($token);
    }

    #[Test]
    public function theContentEncryptionAlgorithmCannotComeFromTheSharedUnprotectedHeader(): void
    {
        $token = $this->createFlattenedToken();
        $enc = $this->moveOutOfTheProtectedHeader($token, 'enc');
        $token['unprotected'] = [
            'enc' => $enc,
        ];

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'The "enc" parameter must be a non-empty string set in the protected header or in the recipient header.'
        );

        $this->decrypt($token);
    }

    /**
     * RFC 7516 puts no location constraint on "enc": only "zip" must occur within the protected header
     * (section 4.1.3). A per-recipient "enc" is therefore unusual, but it is not invalid.
     */
    #[Test]
    public function theContentEncryptionAlgorithmMayComeFromTheRecipientHeader(): void
    {
        $key = $this->createSharedKey();
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
            ])
            ->addRecipient($key, [
                'enc' => 'A128GCM',
            ])
            ->build();
        $token = $this->getJWESerializerManager()
            ->serialize('jwe_json_flattened', $jwe, 0);

        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A128GCM']);

        static::assertTrue($decrypter->decryptUsingKey($jwe, $key, 0));
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    /**
     * In the JSON General Serialization, the key management algorithm legitimately lives in the per-recipient
     * header: it is not part of the AAD and may differ from one recipient to the other (RFC 7516 section 7.2.1).
     */
    #[Test]
    public function theKeyEncryptionAlgorithmMayComeFromTheRecipientHeader(): void
    {
        $key = $this->createSharedKey();
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A256KW', 'A128GCM'])
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'enc' => 'A128GCM',
            ])
            ->addRecipient($key, [
                'alg' => 'A128KW',
            ])
            ->addRecipient($this->createOtherSharedKey(), [
                'alg' => 'A256KW',
            ])
            ->build();
        $token = $this->getJWESerializerManager()
            ->serialize('jwe_json_general', $jwe);

        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'A256KW', 'A128GCM']);

        static::assertTrue($decrypter->decryptUsingKey($jwe, $key, 0));
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    /**
     * The header parameters computed by the key encryption algorithm are added to the per-recipient header
     * when there are several recipients. They must not collide with a shared header, otherwise the builder
     * produces a token that the decrypter, the header checkers and RFC 7516 section 7.2.1 all reject.
     */
    #[Test]
    public function theBuilderNeverProducesDuplicatedHeaderParameters(): void
    {
        $key = $this->createSharedKey();
        $jwe = $this->getJWEBuilderFactory()
            ->create(['PBES2-HS256+A128KW', 'A128GCM'])
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'PBES2-HS256+A128KW',
                'enc' => 'A128GCM',
                'p2c' => 4096,
            ])
            ->addRecipient($key)
            ->addRecipient($this->createOtherSharedKey())
            ->build();
        $token = $this->getJWESerializerManager()
            ->serialize('jwe_json_general', $jwe);

        static::assertArrayNotHasKey('p2c', $jwe->getRecipient(0)->getHeader());

        $jwe = $this->getJWESerializerManager()
            ->unserialize($token);
        $decrypter = $this->getJWEDecrypterFactory()
            ->create(['PBES2-HS256+A128KW', 'A128GCM']);

        static::assertTrue($decrypter->decryptUsingKey($jwe, $key, 0));
        static::assertSame('Live long and prosper.', $jwe->getPayload());
    }

    /**
     * @return array<string, mixed>
     */
    private function createFlattenedToken(): array
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A128KW', 'A128GCM'])
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
            ])
            ->addRecipient($this->createSharedKey())
            ->build();

        return JsonConverter::decode(
            $this->getJWESerializerManager()
                ->serialize('jwe_json_flattened', $jwe)
        );
    }

    /**
     * @param array<string, mixed> $token
     */
    private function moveOutOfTheProtectedHeader(array &$token, string $parameter): mixed
    {
        $protectedHeader = JsonConverter::decode(Base64UrlSafe::decodeNoPadding($token['protected']));
        $value = $protectedHeader[$parameter];
        unset($protectedHeader[$parameter]);
        $token['protected'] = Base64UrlSafe::encodeUnpadded(JsonConverter::encode($protectedHeader));

        return $value;
    }

    /**
     * @param array<string, mixed> $token
     */
    private function decrypt(array $token): void
    {
        $jwe = $this->getJWESerializerManager()
            ->unserialize(JsonConverter::encode($token));
        $this->getJWEDecrypterFactory()
            ->create(['A128KW', 'dir', 'A128GCM', 'A256GCM'])
            ->decryptUsingKey($jwe, $this->createSharedKey(), 0);
    }

    private function createSharedKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg',
        ]);
    }

    private function createOtherSharedKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'iSjSbTfB5aumWmT9v65p2mCVvbLBmrTPLPMhFEHCBJs',
        ]);
    }
}

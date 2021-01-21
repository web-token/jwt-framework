<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Encryption;

use Base64Url\Base64Url;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

/**
 * @group Encrypter
 * @group functional
 *
 * @internal
 */
class EncrypterTest extends EncryptionTest
{
    /**
     * @test
     */
    public function encryptWithJWTInput(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('FOO')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->withAAD('foo,bar,baz')
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;

        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('DEF', $loaded->getSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());
        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals('FOO', $loaded->getPayload());
    }

    /**
     * @test
     */
    public function duplicatedHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: zip.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload('FOO')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient(
                $this->getRSARecipientKey(),
                ['zip' => 'DEF']
            )
        ;
    }

    /**
     * @test
     */
    public function createCompactJWEUsingFactory(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('FOO')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_compact', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('DEF', $loaded->getSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals('FOO', $loaded->getPayload());
    }

    /**
     * @test
     */
    public function createFlattenedJWEUsingFactory(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('FOO')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->withSharedHeader([
                'foo' => 'bar',
            ])
            ->addRecipient(
                $this->getRSARecipientKey(),
                [
                    'plic' => 'ploc',
                ]
            )
            ->withAAD('A,B,C,D')
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('DEF', $loaded->getSharedProtectedHeaderParameter('zip'));
        static::assertEquals('bar', $loaded->getSharedHeaderParameter('foo'));
        static::assertEquals('A,B,C,D', $loaded->getAAD());
        static::assertEquals('ploc', $loaded->getRecipient(0)->getHeaderParameter('plic'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals('FOO', $loaded->getPayload());
    }

    /**
     * @test
     */
    public function encryptAndLoadFlattenedWithAAD(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->withAAD('foo,bar,baz')
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('DEF', $loaded->getSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals($this->getKeyToEncrypt(), new JWK(json_decode($loaded->getPayload(), true)));
    }

    /**
     * @test
     */
    public function compressionAlgorithmNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The compression method "FIP" is not supported.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'FIP',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->withAAD('foo,bar,baz')
            ->build()
        ;
        $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);
    }

    /**
     * @test
     */
    public function foreignKeyManagementModeForbidden(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Foreign key management mode forbidden.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['dir', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
            ])
            ->addRecipient($this->getECDHRecipientPublicKey(), ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW'])
            ->addRecipient($this->getDirectKey(), ['kid' => 'DIR_1', 'alg' => 'dir'])
            ->build()
        ;
    }

    /**
     * @test
     */
    public function operationNotAllowedForTheKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key cannot be used to encrypt');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getSigningKey())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function algorithmNotAllowedForTheKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key is only allowed for algorithm "RSA-OAEP".');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKeyWithAlgorithm())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function encryptAndLoadFlattenedWithDeflateCompression(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['A128CBC-HS256'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256'], ['A128CBC-HS256'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload(json_encode($this->getKeySetToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => '123456789',
                'enc' => 'A128CBC-HS256',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_compact', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('DEF', $loaded->getSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals($this->getKeySetToEncrypt(), JWKSet::createFromKeyData(json_decode($loaded->getPayload(), true)));
    }

    /**
     * @test
     */
    public function algParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Parameter "alg" is missing.');

        $jweBuilder = $this->getJWEBuilderFactory()->create([], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => '123456789',
                'enc' => 'A256CBC-HS512',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function encParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Parameter "enc" is missing.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], [], ['DEF']);

        $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => '123456789',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function notAKeyEncryptionAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The key encryption algorithm "A256CBC-HS512" is not supported or not a key encryption algorithm instance.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['A256CBC-HS512'], ['A256CBC-HS512'], ['DEF']);

        $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => '123456789',
                'enc' => 'A256CBC-HS512',
                'alg' => 'A256CBC-HS512',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function notAContentEncryptionAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The content encryption algorithm "RSA-OAEP-256" is not supported or not a content encryption algorithm instance.');

        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256'], ['RSA-OAEP-256'], ['DEF']);

        $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => '123456789',
                'enc' => 'RSA-OAEP-256',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ])
            ->addRecipient($this->getRSARecipientKey())
            ->build()
        ;
    }

    /**
     * @test
     */
    public function encryptAndLoadCompactWithDirectKeyEncryption(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['dir'], ['A192CBC-HS384'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['dir'], ['A192CBC-HS384'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload(json_encode($this->getKeyToEncrypt()))
            ->withSharedProtectedHeader([
                'kid' => 'DIR_1',
                'enc' => 'A192CBC-HS384',
                'alg' => 'dir',
            ])
            ->addRecipient($this->getDirectKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('dir', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertFalse($loaded->hasSharedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), 0));

        static::assertEquals($this->getKeyToEncrypt(), new JWK(json_decode($loaded->getPayload(), true)));
    }

    /**
     * @test
     */
    public function encryptAndLoadCompactKeyAgreement(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES'], ['A192CBC-HS384'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES'], ['A192CBC-HS384'], ['DEF']);

        $payload = json_encode(['user_id' => '1234', 'exp' => time() + 3600]);
        $jwe = $jweBuilder
            ->create()->withPayload($payload)
            ->withSharedProtectedHeader([
                'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
                'enc' => 'A192CBC-HS384',
                'alg' => 'ECDH-ES',
            ])
            ->addRecipient($this->getECDHRecipientPublicKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('ECDH-ES', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertFalse($loaded->hasSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertEquals($payload, $loaded->getPayload());
    }

    /**
     * @test
     */
    public function encryptAndLoadCompactKeyAgreementWithWrappingCompact(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
                'enc' => 'A256CBC-HS512',
                'alg' => 'ECDH-ES+A256KW',
            ])
            ->addRecipient($this->getECDHRecipientPublicKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertFalse($loaded->hasSharedProtectedHeaderParameter('zip'));
        static::assertFalse($loaded->hasSharedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertTrue(is_string($loaded->getPayload()));
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    /**
     * @test
     */
    public function encryptAndLoadWithGCMAndAAD(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES+A256KW'], ['A256GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['ECDH-ES+A256KW'], ['A256GCM'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
                'enc' => 'A256GCM',
                'alg' => 'ECDH-ES+A256KW',
            ])
            ->withAAD('foo,bar,baz')
            ->addRecipient($this->getECDHRecipientPublicKey())
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_flattened', $jwe, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeaderParameter('alg'));
        static::assertEquals('A256GCM', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertFalse($loaded->hasSharedProtectedHeaderParameter('zip'));
        static::assertFalse($loaded->hasSharedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertTrue(is_string($loaded->getPayload()));
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    /**
     * @test
     */
    public function encryptAndLoadCompactKeyAgreementWithWrapping(): void
    {
        $jweBuilder = $this->getJWEBuilderFactory()->create(['RSA-OAEP-256', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create(['RSA-OAEP-256', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF']);

        $jwe = $jweBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->withSharedProtectedHeader([
                'enc' => 'A256CBC-HS512',
            ])
            ->withAAD('foo,bar,baz')
            ->addRecipient($this->getECDHRecipientPublicKey(), ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW'])
            ->addRecipient($this->getRSARecipientKey(), ['kid' => '123456789', 'alg' => 'RSA-OAEP-256'])
            ->build()
        ;
        $jwe = $this->getJWESerializerManager()->serialize('jwe_json_general', $jwe);

        $loaded = $this->getJWESerializerManager()->unserialize($jwe);

        static::assertEquals(2, $loaded->countRecipients());

        static::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeaderParameter('enc'));
        static::assertEquals('ECDH-ES+A256KW', $loaded->getRecipient(0)->getHeaderParameter('alg'));
        static::assertEquals('RSA-OAEP-256', $loaded->getRecipient(1)->getHeaderParameter('alg'));
        static::assertFalse($loaded->hasSharedHeaderParameter('zip'));
        static::assertFalse($loaded->hasSharedProtectedHeaderParameter('zip'));
        static::assertNull($loaded->getPayload());

        static::assertTrue($jweDecrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), 0));

        static::assertTrue(is_string($loaded->getPayload()));
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    /**
     * @return JWK
     */
    private function getKeyToEncrypt()
    {
        return new JWK([
            'kty' => 'EC',
            'use' => 'enc',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);
    }

    /**
     * @return JWKSet
     */
    private function getKeySetToEncrypt()
    {
        $key = new JWK([
            'kty' => 'EC',
            'use' => 'enc',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return new JWKSet([$key]);
    }

    /**
     * @return JWK
     */
    private function getRSARecipientKey()
    {
        return new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ]);
    }

    /**
     * @return JWK
     */
    private function getRSARecipientKeyWithAlgorithm()
    {
        return new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'alg' => 'RSA-OAEP',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ]);
    }

    /**
     * @return JWK
     */
    private function getSigningKey()
    {
        return new JWK([
            'kty' => 'EC',
            'key_ops' => ['sign', 'verify'],
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);
    }

    /**
     * @return JWK
     */
    private function getECDHRecipientPublicKey()
    {
        return new JWK([
            'kty' => 'EC',
            'key_ops' => ['encrypt', 'decrypt'],
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);
    }

    /**
     * @return JWK
     */
    private function getDirectKey()
    {
        return new JWK([
            'kid' => 'DIR_1',
            'key_ops' => ['encrypt', 'decrypt'],
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
        ]);
    }

    private function getPrivateKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ],
            [
                'kid' => '2010-12-29',
                'kty' => 'RSA',
                'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                'e' => 'AQAB',
                'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            ],
            [
                'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            ],
            [
                'kid' => '123456789',
                'kty' => 'RSA',
                'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e' => 'AQAB',
                'p' => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd' => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q' => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp' => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq' => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi' => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
            ],
            [
                'kty' => 'RSA',
                'n' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
                'e' => 'AQAB',
                'd' => 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
                'p' => '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
                'q' => 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
                'dp' => 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
                'dq' => 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
                'qi' => 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY',
            ],
            [
                'kty' => 'RSA',
                'n' => 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw',
                'e' => 'AQAB',
                'd' => 'VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ',
                'p' => '9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM',
                'q' => 'uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0',
                'dp' => 'w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs',
                'dq' => 'o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU',
                'qi' => 'eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo',
            ],
            [
                'kty' => 'RSA',
                'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                'e' => 'AQAB',
                'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
                'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
                'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
                'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
                'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
                'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd' => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
            ],
        ]];

        return JWKSet::createFromKeyData($keys);
    }

    private function getSymmetricKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => 'DIR_1',
                'kty' => 'oct',
                'k' => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
            ],
            [
                'kty' => 'oct',
                'k' => 'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q',
            ],
            [
                'kty' => 'oct',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ],
            [
                'kty' => 'oct',
                'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
            ],
        ]];

        return JWKSet::createFromKeyData($keys);
    }
}

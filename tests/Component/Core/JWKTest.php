<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class JWKTest extends TestCase
{
    #[Test]
    public function aKeyContainsAllExpectedParameters(): void
    {
        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sig',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        static::assertSame('EC', $jwk->get('kty'));
        static::assertSame('ES256', $jwk->get('alg'));
        static::assertSame('sig', $jwk->get('use'));
        static::assertFalse($jwk->has('kid'));
        static::assertSame(['sign'], $jwk->get('key_ops'));
        static::assertSame('P-256', $jwk->get('crv'));
        static::assertFalse($jwk->has('x5u'));
        static::assertFalse($jwk->has('x5c'));
        static::assertFalse($jwk->has('x5t'));
        static::assertFalse($jwk->has('x5t#256'));
        static::assertSame('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        static::assertSame('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        static::assertSame(
            '{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","key_ops":["sign"],"alg":"ES256","bar":"plic"}',
            json_encode($jwk, JSON_THROW_ON_ERROR)
        );
        static::assertSame('oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U', $jwk->thumbprint('sha256'));
        static::assertSame('EMMMl6Rj75mqhcABihxxl_VCN9s', $jwk->thumbprint('sha1'));
        static::assertSame('dqwHnan4iJ1_eEll-o4Egw', $jwk->thumbprint('md5'));
    }

    #[Test]
    public function iCannotGetTheThumbprintOfTheKeyWhenIUseAnUnsupportedHashingAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm "foo" is not supported.');

        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sig',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->thumbprint('foo');
    }

    #[Test]
    public function iMustSetAtLeastTheKtyParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The parameter "kty" is mandatory.');

        new JWK([]);
    }

    #[Test]
    public function iCannotGetAParameterThatDoesNotExist(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The value identified by "ABCD" does not exist.');

        $jwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    #[Test]
    public function iCanConvertAPrivateKeyIntoPublicKey(): void
    {
        $private = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $public = $private->toPublic();

        static::assertSame(json_encode([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]), json_encode($public, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public static function convertToPEM(): void
    {
        // Given
        $key = '{"kty":"EC","crv":"P-256","x":"GDDdmNtwNvlXN04SEUp20BZJ9im6SQqkP8u4d8G6RAk","y":"AIAxkBwTTqbCcNbqbpk8l_Eh-4KtpgyyHkNJ6K4jnvOv","use":"sig","alg":"ES256","kid":"ayRrlw","key_ops":["verify"]}';
        $jwk = JWK::createFromJson($key);
        $expectedPEM = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGDDdmNtwNvlXN04SEUp20BZJ9im6
SQqkP8u4d8G6RAmAMZAcE06mwnDW6m6ZPJfxIfuCraYMsh5DSeiuI57zrw==
-----END PUBLIC KEY-----

PEM;

        //When
        $pem = ECKey::convertToPEM($jwk);

        //Then
        static::assertSame($expectedPEM, $pem);
    }
}

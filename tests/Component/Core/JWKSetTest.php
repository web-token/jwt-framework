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

namespace Jose\Tests\Component\Core;

use function count;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @group JWKSet
 *
 * @internal
 */
class JWKSetTest extends TestCase
{
    /**
     * @test
     */
    public function iCanSelectAKeyInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc');
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     */
    public function iCannotSelectAKeyFromAKeySetWithUnsupportedUsageParameter(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Allowed key types are "sig" or "enc".');

        $jwkset = $this->getPublicKeySet();
        $jwkset->selectKey('foo');
    }

    /**
     * @test
     */
    public function iCannotCreateAKeySetWithBadArguments(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid data.');

        JWKSet::createFromKeyData(['keys' => true]);
    }

    /**
     * @test
     */
    public function iCanGetAllKeysInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();
        static::assertEquals(3, count($jwkset->all()));
    }

    /**
     * @test
     */
    public function iCanAddKeysInAKeySet(): void
    {
        $jwkset = $this->getPublicKeySet();
        $new_jwkset = $jwkset->with(new JWK(['kty' => 'none']));
        static::assertEquals(4, count($new_jwkset->all()));
        static::assertNotSame($jwkset, $new_jwkset);
    }

    /**
     * @test
     */
    public function iCanSelectAKeyWithAlgorithm(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', new FooAlgorithm());
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertEquals(
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'enc',
            ],
            $jwk->all()
        );
    }

    /**
     * @test
     */
    public function iCanSelectAKeyWithAlgorithmAndKeyId(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', new FooAlgorithm(), ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertEquals(
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            $jwk->all()
        );
    }

    /**
     * @test
     */
    public function iCanSelectAKeyWithWithKeyId(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertEquals(
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            $jwk->all()
        );
    }

    /**
     * @test
     */
    public function theKeySetDoesNotContainsSuitableAKeyThatFitsOnTheRequirements(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        static::assertNull($jwk);
    }

    /**
     * @test
     */
    public function iCanCreateAKeySetUsingValues(): void
    {
        $values = ['keys' => [[
            'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'sig',
        ]]];
        $jwkset = JWKSet::createFromKeyData($values);
        static::assertEquals(1, count($jwkset));
        static::assertTrue($jwkset->has('71ee230371d19630bc17fb90ccf20ae632ad8cf8'));
        static::assertFalse($jwkset->has(0));
    }

    /**
     * @test
     */
    public function keySet(): void
    {
        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
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

        $jwkset = new JWKSet([$jwk1]);
        $jwkset = $jwkset->with($jwk2);

        static::assertEquals('{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}', json_encode($jwkset));
        static::assertEquals(2, count($jwkset));
        static::assertEquals(2, $jwkset->count());
        static::assertTrue($jwkset->has('0123456789'));
        static::assertTrue($jwkset->has('9876543210'));
        static::assertFalse($jwkset->has(0));

        foreach ($jwkset as $key) {
            static::assertEquals('EC', $key->get('kty'));
        }

        static::assertEquals('9876543210', $jwkset->get('9876543210')->get('kid'));
        $jwkset = $jwkset->without('9876543210');
        $jwkset = $jwkset->without('9876543210');

        static::assertEquals(1, count($jwkset));
        static::assertEquals(1, $jwkset->count());

        $jwkset = $jwkset->without('0123456789');
        static::assertEquals(0, $jwkset->count());
    }

    /**
     * @test
     */
    public function keySet2(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Undefined index.');

        $jwk1 = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = new JWK([
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

        $jwkset = new JWKSet([$jwk1, $jwk2]);

        $jwkset->get(2);
    }

    private function getPublicKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'enc',
            ],
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ],
        ]];

        return JWKSet::createFromKeyData($keys);
    }
}

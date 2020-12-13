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

namespace Jose\Tests\Component\KeyManagement\Keys;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use PHPUnit\Framework\TestCase;

/**
 * @group ECKeys
 * @group unit
 *
 * @internal
 */
class ECKeysTest extends TestCase
{
    /**
     * @test
     */
    public function keyTypeNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key type');

        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'DSA'.DIRECTORY_SEPARATOR.'DSA.key';
        KeyConverter::loadFromKeyFile($file);
    }

    /**
     * @see https://github.com/Spomky-Labs/jose/issues/141
     * @see https://gist.github.com/Spomky/246eca6aaeeb7a40f11d3a2d98960282
     *
     * @test
     */
    public function loadPrivateEC256KeyGenerateByAPN(): void
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.from.APN.key');
        $details = KeyConverter::loadFromKey($pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '13n3isfsEktzl-CtH5ECpRrKk-40prVuCbldkP77gak',
            'x' => 'YcIMUkalwbeeAVkUF6FP3aBVlCzlqxEd7i0uN_4roA0',
            'y' => 'bU8wOWJBkTNZ61gB1_4xp-r8-uVsQB8D6Xsl-aKMCy8',
        ]);
    }

    /**
     * @test
     */
    public function loadPublicEC256Key(): void
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es256.key');
        $details = KeyConverter::loadFromKey($pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    /**
     * @test
     */
    public function loadPrivateEC256Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.key');
        $details = KeyConverter::loadFromKey($private_pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    /**
     * @test
     */
    public function loadEncryptedPrivateEC256Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.encrypted.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    /**
     * @test
     */
    public function loadEncryptedPrivateEC256KeyWithoutPassword(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Password required for encrypted keys.');

        KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.encrypted.key');
    }

    /**
     * @test
     */
    public function loadPublicEC384Key(): void
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es384.key');
        $details = KeyConverter::loadFromKey($pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    /**
     * @test
     */
    public function loadPrivateEC384Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es384.key');
        $details = KeyConverter::loadFromKey($private_pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    /**
     * @test
     */
    public function loadEncryptedPrivateEC384Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es384.encrypted.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    /**
     * @test
     */
    public function loadPublicEC512Key(): void
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es512.key');
        $details = KeyConverter::loadFromKey($pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    /**
     * @test
     */
    public function loadPrivateEC512Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es512.key');
        $details = KeyConverter::loadFromKey($private_pem);
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    /**
     * @test
     */
    public function loadEncryptedPrivateEC512Key(): void
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es512.encrypted.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    /**
     * @test
     */
    public function convertPrivateKeyToPublic(): void
    {
        $jwk = new JWK([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ]);

        static::assertEquals([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ], $jwk->toPublic()->all());
    }

    /**
     * @test
     */
    public function createECKeyOnP256(): void
    {
        $jwk = JWKFactory::createECKey('P-256');

        static::assertEquals('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }

    /**
     * @test
     */
    public function createECKeyOnP384(): void
    {
        $jwk = JWKFactory::createECKey('P-384');

        static::assertEquals('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }

    /**
     * @test
     */
    public function createECKeyOnP521(): void
    {
        $jwk = JWKFactory::createECKey('P-521');

        static::assertEquals('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }
}

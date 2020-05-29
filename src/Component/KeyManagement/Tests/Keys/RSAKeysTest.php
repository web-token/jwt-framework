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

namespace Jose\Component\KeyManagement\Tests\Keys;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;
use PHPUnit\Framework\TestCase;

/**
 * @group RSAKeys
 * @group unit
 *
 * @internal
 */
class RSAKeysTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7638#section-3.1
     *
     * @test
     */
    public function keyThumbprint(): void
    {
        $key = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        static::assertEquals('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $key->thumbprint('sha256'));
    }

    /**
     * @test
     */
    public function hashAlgorithmNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The hash algorithm "foo" is not supported.');

        $key = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
            'alg' => 'RS256',
            'kid' => '2011-04-29',
        ]);

        $key->thumbprint('foo');
    }

    /**
     * @test
     */
    public function unsupportedKeyType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWK is not a RSA key');

        RSAKey::createFromJWK(new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]));
    }

    /**
     * @test
     */
    public function loadPublicRSAKeyFromPEM(): void
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'public.key';
        $rsa_key = RSAKey::createFromPEM($file);

        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ], $rsa_key->toArray());
        static::assertTrue($rsa_key->isPublic());
    }

    /**
     * @test
     */
    public function loadPublicRSAKeyFromJWK(): void
    {
        $jwk = new JWK([
            'kty' => 'RSA',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
            'use' => 'sig',
            'key_ops' => ['sign', 'verify'],
        ]);
        $rsa_key = RSAKey::createFromJWK($jwk);

        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
            'use' => 'sig',
            'key_ops' => ['sign', 'verify'],
        ], $rsa_key->toArray());
        static::assertTrue($rsa_key->isPublic());
    }

    /**
     * @test
     */
    public function loadPublicRSAKeyFromValues(): void
    {
        $rsa_key = RSAKey::createFromJWK(new JWK([
            'kty' => 'RSA',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ]));

        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ], $rsa_key->toArray());
        static::assertTrue($rsa_key->isPublic());
    }

    /**
     * @test
     */
    public function loadPrivateRSAKey(): void
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'private.key';
        $rsa_key = RSAKey::createFromPEM($file);

        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());
        static::assertFalse($rsa_key->isPublic());

        $public_key = RSAKey::toPublic($rsa_key);
        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
        ], $public_key->toArray());
        static::assertTrue($public_key->isPublic());
    }

    /**
     * @test
     */
    public function loadPrivateRSAKeyFromJWK(): void
    {
        $jwk = new JWK([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ]);
        $rsa_key = RSAKey::createFromJWK($jwk);

        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());
        static::assertFalse($rsa_key->isPublic());

        $public_key = RSAKey::toPublic($rsa_key);
        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
        ], $public_key->toArray());
        static::assertTrue($public_key->isPublic());
    }

    /**
     * @test
     */
    public function loadPrivateRSAKeyFromValues(): void
    {
        $rsa_key = RSAKey::createFromJWK(new JWK([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ]));

        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
        ], $rsa_key->toArray());

        static::assertFalse($rsa_key->isPublic());

        $public_key = RSAKey::toPublic($rsa_key);
        static::assertEquals([
            'kty' => 'RSA',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
        ], $public_key->toArray());
        static::assertTrue($public_key->isPublic());
    }

    /**
     * @test
     */
    public function convertPrivateKeyToPublic(): void
    {
        $private_ec_key = RSAKey::createFromJWK(new JWK([
            'kty' => 'RSA',
            'kid' => 'Foo',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'p' => '9Vovb8pySyOZUoTrNMD6JmTsDa12u9y4_HImQuKD0rerVo2y5y7D_r00i1MhGHkBrI3W2PsubIiZgKp1f0oQfQ',
            'd' => 'jrDrO3Fo2GvD5Jn_lER0mnxtIb_kvYt5WyaYutbRN1u_SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXwqDrFF7NDebw95g6JzI-SbkIHw0Cb-_E9K92FjvW3Bi8j9PKIa8c_dpwIAIirc_q8uhSTf4WoIOHSFbSaQPE',
            'q' => '6Sgna9gQw4dXN0jBSjOZSjl4S2_H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZtsyVZQ',
            'dp' => '5m79fpE1Jz0YE1ijT7ivOMAws-fnTCnR08eiB8-W36GBWplbHaXejrJFV1WMD-AWomnVD5VZ1LW29hEiqZp2QQ',
            'dq' => 'JV2pC7CB50QeZx7C02h3jZyuObC9YHEEoxOXr9ZPjPBVvjV5S6NVajQsdEu4Kgr_8YOqaWgiHovcxTwyqcgZvQ',
            'qi' => 'VZykPj-ugKQxuWTSE-hA-nJqkl7FzjfzHte4QYUSHLHFq6oLlHhgUoJ_4oFLaBmCvgZLAFRDDD6pnd5Fgzt9ow',
            'foo' => 'bar',
        ]));

        $public_ec_key = RSAKey::toPublic($private_ec_key);

        static::assertEquals([
            'kty' => 'RSA',
            'kid' => 'Foo',
            'n' => '33WRDEG5rN7daMgI2N5H8cPwTeQPOnz34uG2fe0yKyHjJDGE2XoESRpu5LelSPdYM_r4AWMFWoDWPd-7xaq7uFEkM8c6zaQIgj4uEiq-pBMvH-e805SFbYOKYqfQe4eeXAk4OrQwcUkSrlGskf6YUaw_3IwbPgzEDTgTZFVtQlE',
            'e' => 'AQAB',
            'foo' => 'bar',
        ], $public_ec_key->toArray());
    }

    /**
     * @test
     */
    public function createRSAKey512Bits(): void
    {
        $jwk = JWKFactory::createRSAKey(512);

        static::assertEquals('RSA', $jwk->get('kty'));
        static::assertTrue($jwk->has('p'));
        static::assertTrue($jwk->has('n'));
        static::assertTrue($jwk->has('q'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('dp'));
        static::assertTrue($jwk->has('dq'));
        static::assertTrue($jwk->has('qi'));
    }

    /**
     * @test
     */
    public function loadPrivateRSAKeyFromMinimalValues(): void
    {
        $rsa_key = RSAKey::createFromJWK(new JWK([
            'kty' => 'RSA',
            'n' => 'gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw',
            'e' => 'AQAB',
            'd' => 'JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ',
        ]));

        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw',
            'e' => 'AQAB',
            'd' => 'JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ',
        ], $rsa_key->toArray());

        $rsa_key->optimize();

        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw',
            'e' => 'AQAB',
            'p' => 'pxyF-Ao17wl4ADI0YSsNYm9OzZz6AZD9cUxbxvX-z3yR_vH2GExdcOht5UD9Ij9r0ZyHKkmWGKCtrYzr-Qi2ia2vyiZU0wGmxR_fadHnkxfIqW78ME5C-xGoWLBtHlTaPCWSEmv3p5vM2fqZeUdqTxzb0bQABt0fI6HPjvBlI0s',
            'd' => 'JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ',
            'q' => 'xiSp6dbdYGINxtklTJlzVr91u_GJzWqyyA4t0jhuWrQN7dLW0s_3I9x6Pdk5U19j0iLWBwcutY9e5SyWPoF0lYVIowZeW0jNiOtv0NthayJ3HJpPk8kj6sVlH0y4sKN_WWHhU5leTwOpr8IG-yohKRyV6Xwhu_JLkzKKWod21QE',
            'dp' => 'pYUyCNGMRDx7uK4BhbEP68zWIAB4_K4w6lS4nuQvRDJdpUjh-YVCFECUATwSviZVU-QXWUJTwgb8n-byH9OKgeogMTkwUWPUXHHKZ1T6a45mObRtZCdQXsBJn7b4Dc_77RFFkquQPFqsV8fI1gBvgvbRn-8LC8FfQ3rVS_4-Hus',
            'dq' => 'rNTcNPFLhj_hPnq4UzliZt94RaipB7mzGldr1nuMnqeBotmOsrHeI7S0F_C7VSLWgjwKrnSwZIQbRRGAOCNZWva4ZiMu-LbnOTAMB4TkU7vrY9Kh6QnAv47Q5t1YGBN1CLUdA3u6zHcocvtudXTJGgAqL1AsaLEvBMVH8zFIEQE',
            'qi' => 'bbFp1zSfnmmOUYUtbaKhmFofn0muf1PrnMGq6zeu8zruf3gK9Y1oDsUk54FlV0mNBO3_t3Zbw2752CLklt73zesVeF-Nsc1kDnx_WGf4YrQpLh5PvkEfT_wPbveKTTcVXiVxMPHHZ-n2kOe3oyShycSLP5_I_SYN-loZHu7QC_I',
        ], $rsa_key->toArray());

        static::assertFalse($rsa_key->isPublic());

        $public_key = RSAKey::toPublic($rsa_key);
        static::assertEquals([
            'kty' => 'RSA',
            'n' => 'gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw',
            'e' => 'AQAB',
        ], $public_key->toArray());
        static::assertTrue($public_key->isPublic());
    }
}

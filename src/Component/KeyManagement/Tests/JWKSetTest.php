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

namespace Jose\Component\KeyManagement\Tests;

use function count;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
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
    public function keySelection(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc');
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     */
    public function keySelectionWithAlgorithm(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', new FooAlgorithm());
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertEquals(
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
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
    public function keySelectionWithAlgorithmAndKeyId(): void
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
    public function keySelectionWithKeyId(): void
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
    public function keySelectionReturnsNothing(): void
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        static::assertNull($jwk);
    }

    /**
     * @test
     */
    public function createKeySetFromValues(): void
    {
        $values = ['keys' => [[
            'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
            'kty' => 'FOO',
            'alg' => 'foo',
            'use' => 'sig',
        ]]];
        $jwkset = JWKFactory::createFromValues($values);
        static::assertInstanceOf(JWKSet::class, $jwkset);
        static::assertEquals(1, count($jwkset));
        static::assertTrue($jwkset->has('71ee230371d19630bc17fb90ccf20ae632ad8cf8'));
        static::assertFalse($jwkset->has(0));
    }

    private function getPublicKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'FOO',
                'alg' => 'foo',
                'use' => 'sig',
            ],
            [
                'kty' => 'RSA',
                'n' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
                'e' => 'AQAB',
            ],
            [
                'kty' => 'RSA',
                'n' => 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw',
                'e' => 'AQAB',
            ],
            [
                'kty' => 'RSA',
                'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                'e' => 'AQAB',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            ],
        ]];

        return JWKSet::createFromKeyData($keys);
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWS;

/**
 * @group None
 * @group Unit
 */
class NoneSignatureTest extends SignatureTest
{
    public function testNoneSignAndVerifyAlgorithm()
    {
        $key = JWK::create([
            'kty' => 'none',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $signature = $none->sign($key, $data);

        self::assertEquals($signature, '');
        self::assertTrue($none->verify($key, $data, $signature));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     */
    public function testInvalidKey()
    {
        $key = JWK::create([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $none->sign($key, $data);
    }

    public function testNoneSignAndVerifyComplete()
    {
        $jwk = JWK::create([
            'kty' => 'none',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['none']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($jwk, ['alg' => 'none'])
            ->build();

        self::assertEquals(1, $jws->countSignatures());

        $compact = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
        self::assertTrue(is_string($compact));

        $result = $this->getJWSSerializerManager()->unserialize($compact);

        self::assertInstanceOf(JWS::class, $result);

        self::assertEquals('Live long and Prosper.', $result->getPayload());
        self::assertEquals(1, $result->countSignatures());
        self::assertTrue($result->getSignature(0)->hasProtectedHeaderParameter('alg'));
        self::assertEquals('none', $result->getSignature(0)->getProtectedHeaderParameter('alg'));
    }
}

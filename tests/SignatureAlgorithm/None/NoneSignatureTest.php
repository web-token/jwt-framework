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

namespace Jose\Tests\Component\Signature\Algorithm;

use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

/**
 * @group None
 * @group unit
 *
 * @internal
 */
class NoneSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function noneSignAndVerifyAlgorithm(): void
    {
        $key = new JWK([
            'kty' => 'none',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $signature = $none->sign($key, $data);

        static::assertEquals($signature, '');
        static::assertTrue($none->verify($key, $data, $signature));
    }

    /**
     * @test
     */
    public function invalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $none->sign($key, $data);
    }

    /**
     * @test
     */
    public function noneSignAndVerifyComplete(): void
    {
        $jwk = new JWK([
            'kty' => 'none',
        ]);

        $jwsBuilder = new JWSBuilder(
            new AlgorithmManager([new None()])
        );
        $serializer = new CompactSerializer(
        );
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($jwk, ['alg' => 'none'])
            ->build()
        ;

        static::assertEquals(1, $jws->countSignatures());

        $compact = $serializer->serialize($jws, 0);
        static::assertTrue(is_string($compact));

        $result = $serializer->unserialize($compact);

        static::assertEquals('Live long and Prosper.', $result->getPayload());
        static::assertEquals(1, $result->countSignatures());
        static::assertTrue($result->getSignature(0)->hasProtectedHeaderParameter('alg'));
        static::assertEquals('none', $result->getSignature(0)->getProtectedHeaderParameter('alg'));
    }
}

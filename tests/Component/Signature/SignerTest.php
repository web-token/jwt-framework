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

namespace Jose\Tests\Component\Signature;

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\CompactSerializer;
use LogicException;

/**
 * @group Signer
 * @group functional
 *
 * @internal
 */
class SignerTest extends SignatureTest
{
    /**
     * @test
     */
    public function algParameterIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No "alg" parameter set in the header.');

        $jwsBuilder = $this->getJWSBuilderFactory()->create([]);
        $jwsBuilder
            ->create()->withPayload(json_encode($this->getKey3()))
            ->addSignature($this->getKey1(), [])
            ->build()
        ;
    }

    /**
     * @test
     */
    public function algParameterIsNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "foo" is not supported.');

        $jwsBuilder = $this->getJWSBuilderFactory()->create([]);
        $jwsBuilder
            ->create()->withPayload(json_encode($this->getKey3()))
            ->addSignature($this->getKey1(), ['alg' => 'foo'])
            ->build()
        ;
    }

    /**
     * @test
     */
    public function duplicatedHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header contains duplicated entries: foo.');

        $jwsBuilder = $this->getJWSBuilderFactory()->create([]);
        $jwsBuilder
            ->create()->withPayload(json_encode($this->getKey3()))
            ->addSignature($this->getKey1(), ['alg' => 'ES256', 'foo' => 'bar'], ['foo' => 'bar'])
        ;
    }

    /**
     * @test
     */
    public function signAndLoadCompact(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload(json_encode($this->getKey3()))
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        static::assertEquals(2, $jws->countSignatures());

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));

        static::assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeaderParameter('alg'));
    }

    /**
     * @test
     */
    public function signMultipleInstructionWithCompactRepresentation(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        static::assertEquals(2, $jws->countSignatures());
        static::assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0));
        static::assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 1));
    }

    /**
     * @group JWSBuilder
     *
     * @test
     */
    public function signMultipleInstructionWithCompactRepresentationUsingBuilder(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        static::assertEquals(2, $jws->countSignatures());
        static::assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0));
        static::assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 1));
    }

    /**
     * @group JWSBuilder
     *
     * @test
     */
    public function signMultipleInstructionWithCompactRepresentationUsingBuilderAndDetachedPayload(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.', true)
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        static::assertEquals(2, $jws->countSignatures());
        static::assertEquals('eyJhbGciOiJIUzUxMiJ9..TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0));
        static::assertEquals('eyJhbGciOiJSUzUxMiJ9..cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 1));
    }

    /**
     * @test
     */
    public function createCompactJWSUsingFactory(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS512', 'RS512']);

        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;
        $jws0 = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
        $jws1 = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 1);

        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.', true)
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;
        $jws2 = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
        $jws3 = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 1);

        static::assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws0);
        static::assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws1);
        static::assertEquals('eyJhbGciOiJIUzUxMiJ9..TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws2);
        static::assertEquals('eyJhbGciOiJSUzUxMiJ9..cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws3);

        $loaded_0 = $this->getJWSSerializerManager()->unserialize($jws0);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_0, $this->getKey1(), 0));

        $loaded_1 = $this->getJWSSerializerManager()->unserialize($jws1);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_1, $this->getKey2(), 0));

        $loaded_2 = $this->getJWSSerializerManager()->unserialize($jws2);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_2, $this->getKey1(), 0, 'Live long and Prosper.'));

        $loaded_3 = $this->getJWSSerializerManager()->unserialize($jws3);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_3, $this->getKey2(), 0, 'Live long and Prosper.'));
    }

    /**
     * @test
     */
    public function signMultipleInstructionWithFlattenedRepresentation(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        static::assertEquals(2, $jws->countSignatures());
        static::assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJIUzUxMiJ9","signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0));
        static::assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJSUzUxMiJ9","signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 1));
    }

    /**
     * @test
     */
    public function createFlattenedJWSUsingFactory(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'], ['plic' => 'ploc'])
            ->build()
        ;
        $jws0 = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);
        $jws1 = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 1);

        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.', true)
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'], ['plic' => 'ploc'])
            ->build()
        ;
        $jws2 = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);
        $jws3 = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 1);

        static::assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar"},"signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $jws0);
        static::assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJSUzUxMiJ9","header":{"plic":"ploc"},"signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $jws1);
        static::assertEquals('{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar"},"signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $jws2);
        static::assertEquals('{"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"plic":"ploc"},"signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $jws3);

        $loaded_0 = $this->getJWSSerializerManager()->unserialize($jws0);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_0, $this->getKey1(), 0));

        $loaded_1 = $this->getJWSSerializerManager()->unserialize($jws1);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_1, $this->getKey2(), 0));

        $loaded_2 = $this->getJWSSerializerManager()->unserialize($jws2);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_2, $this->getKey1(), 0, 'Live long and Prosper.'));

        $loaded_3 = $this->getJWSSerializerManager()->unserialize($jws3);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_3, $this->getKey2(), 0, 'Live long and Prosper.'));
    }

    /**
     * @test
     */
    public function algorithmNotAllowedForTheKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The algorithm "RS512" is not allowed with this key.');

        $jwsBuilder = $this->getJWSBuilderFactory()->create([]);
        $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey5(), ['alg' => 'RS512'])
            ->build()
        ;
    }

    /**
     * @test
     */
    public function operationNotAllowedForTheKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key cannot be used to sign');

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['PS512']);
        $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey4(), ['alg' => 'PS512'])
            ->build()
        ;
    }

    /**
     * @test
     */
    public function signAndLoadFlattened(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512']);
        $jws = $jwsBuilder
            ->create()->withPayload(json_encode(['baz', 'ban']))
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0));

        static::assertEquals(1, $loaded->countSignatures());
        static::assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
    }

    /**
     * @test
     */
    public function signAndLoad(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));

        static::assertEquals(2, $loaded->countSignatures());
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());
        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getPublicKeySet(), 1));

        static::assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeaderParameter('alg'));
    }

    /**
     * @test
     */
    public function signAndLoadWithWrongKeys(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));

        static::assertEquals(1, $loaded->countSignatures());
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());

        static::assertFalse($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
    }

    /**
     * @test
     */
    public function signAndLoadWithUnsupportedAlgorithm(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));

        static::assertEquals(1, $loaded->countSignatures());
        static::assertEquals('Live long and Prosper.', $loaded->getPayload());

        static::assertFalse($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
    }

    /**
     * @test
     */
    public function signAndLoadWithJWSWithoutSignatures(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The JWS does not contain any signature.');

        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $jws = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[]}';

        $jwsVerifier = $this->getJWSVerifierFactory()->create([]);
        $loaded = $this->getJWSSerializerManager()->unserialize($jws);

        static::assertEquals(0, $loaded->countSignatures());
        static::assertEquals($payload, $loaded->getPayload());

        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     *
     * @test
     */
    public function compactJSONWithUnencodedPayloadFailsBecauseOfForbiddenCharacters(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Unable to convert the JWS with non-encoded payload.');

        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper.')
            ->addSignature($key, $protectedHeader)
            ->build()
        ;

        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     *
     * @test
     */
    public function compactJSONWithUnencodedPayloadSucceeded(): void
    {
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload('Live long and Prosper~')
            ->addSignature($key, $protectedHeader)
            ->build()
        ;

        $compact = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
        static::assertEquals('eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.Live long and Prosper~.nUNenbjNAEH2nNIXyQYmutiHRPnT17HcaMr5Lsho4BE', $compact);

        $loaded = $this->getJWSSerializerManager()->unserialize($compact, $serializer);
        static::assertEquals(CompactSerializer::NAME, $serializer);
        static::assertEquals('Live long and Prosper~', $loaded->getPayload());
        static::assertEquals('Live long and Prosper~', $loaded->getEncodedPayload());
        static::assertEquals($protectedHeader, $loaded->getSignature(0)->getProtectedHeader());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     *
     * @test
     */
    public function compactJSONWithUnencodedDetachedPayload(): void
    {
        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $jws = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
        static::assertEquals('eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY', $jws);

        $loaded = $this->getJWSSerializerManager()->unserialize($jws);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded, $key, 0, $payload));

        static::assertEquals($protectedHeader, $loaded->getSignature(0)->getProtectedHeader());
    }

    /**
     * The library is able to support multiple payload encoding and conversion in JSON if payload is detached.
     *
     * @test
     */
    public function compactJSONWithUnencodedDetachedPayloadAndMultipleSignatures(): void
    {
        $payload = '$.02';
        $protectedHeader1 = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];
        $protectedHeader2 = [
            'alg' => 'HS512',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256', 'HS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS256', 'HS512']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader1)
            ->addSignature($key, $protectedHeader2)
            ->build()
        ;

        $expected_result = '{"signatures":[{"signature":"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY","protected":"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"},{"signature":"Mp-m-Vyst0zYCNkpg2RiIN8W9GO4nLU3FKsFtHzEcP4tgR4QcMys1_2m9HrDwszi0Cp2gv_Lioe6UPCcTNn6tQ","protected":"eyJhbGciOiJIUzUxMiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"}]}';

        static::assertEquals($expected_result, $this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));

        $loaded = $this->getJWSSerializerManager()->unserialize($expected_result);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded, $key, 0, $payload));
        static::assertEquals($protectedHeader1, $loaded->getSignature(0)->getProtectedHeader());
    }

    /**
     * The library is able to support multiple payload encoding and conversion in JSON is not available if payload is not detached.
     *
     * @test
     */
    public function compactJSONWithUnencodedPayloadAndMultipleSignatures(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Foreign payload encoding detected.');

        $payload = '$.02';
        $protectedHeader1 = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];
        $protectedHeader2 = [
            'alg' => 'HS256',
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload)
            ->addSignature($key, $protectedHeader1)
            ->addSignature($key, $protectedHeader2)
            ->build()
        ;

        $this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0);
    }

    /**
     * @test
     */
    public function jWSWithUnencodedPayloadButNoCritHeader(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');

        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @test
     */
    public function jWSWithUnencodedPayloadButCritHeaderIsNotAnArray(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The protected header parameter "crit" must be an array.');

        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => 'foo',
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @test
     */
    public function jWSWithUnencodedPayloadButCritHeaderDoesNotContainB64(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');

        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['foo'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     *
     * @test
     */
    public function flattenedJSONWithUnencodedPayload(): void
    {
        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $expected_result = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
            'payload' => '$.02',
            'signature' => 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY',
        ];

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $jws = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);

        static::assertEquals($expected_result, json_decode($jws, true));

        $loaded = $this->getJWSSerializerManager()->unserialize($jws);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded, $key, 0));

        static::assertEquals($payload, $loaded->getPayload());
        static::assertEquals($protectedHeader, $loaded->getSignature(0)->getProtectedHeader());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     *
     * @test
     */
    public function flattenedJSONWithUnencodedDetachedPayload(): void
    {
        $payload = '$.02';
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];

        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $expected_result = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
            'signature' => 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY',
        ];

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS256']);
        $jws = $jwsBuilder
            ->create()->withPayload($payload, true)
            ->addSignature($key, $protectedHeader)
            ->build()
        ;
        $jws = $this->getJWSSerializerManager()->serialize('jws_json_flattened', $jws, 0);

        static::assertEquals($expected_result, json_decode($jws, true));
    }

    /**
     * @test
     */
    public function signAndLoadWithoutAlgParameterInTheHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No "alg" parameter set in the header.');

        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $jws = 'eyJraWQiOiJiaWxiby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUifQ.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg';

        $jwsVerifier = $this->getJWSVerifierFactory()->create([]);
        $loaded = $this->getJWSSerializerManager()->unserialize($jws);

        static::assertEquals(1, $loaded->countSignatures());
        static::assertEquals($payload, $loaded->getPayload());

        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
    }

    /**
     * @test
     */
    public function signAndLoadJWKSet(): void
    {
        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload(json_encode($this->getKeyset()))
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));
        static::assertEquals(2, $loaded->countSignatures());
        static::assertEquals($this->getKeyset(), JWKSet::createFromKeyData(json_decode($loaded->getPayload(), true)));
        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet(), 0));
        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, $this->getPublicKeySet(), 1));

        static::assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeaderParameter('alg'));
    }

    /**
     * @test
     */
    public function keySetIsEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no key in the key set.');

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['HS512', 'RS512']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['HS512', 'RS512']);
        $jws = $jwsBuilder
            ->create()->withPayload(json_encode($this->getKeyset()))
            ->addSignature($this->getKey1(), ['alg' => 'HS512', ['foo' => 'bar']])
            ->addSignature($this->getKey2(), ['alg' => 'RS512'])
            ->build()
        ;

        $loaded = $this->getJWSSerializerManager()->unserialize($this->getJWSSerializerManager()->serialize('jws_json_general', $jws, 0));
        static::assertEquals(2, $loaded->countSignatures());
        static::assertEquals($this->getKeyset(), JWKSet::createFromKeyData(json_decode($loaded->getPayload(), true)));
        static::assertTrue($jwsVerifier->verifyWithKeySet($loaded, new JWKSet([]), 0));
        static::assertTrue($jwsVerifier->verifyWithKey($loaded, new JWK(['kty' => 'EC']), 1));
    }

    private function getKey1(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
    }

    private function getKey2(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'use' => 'sig',
            'key_ops' => ['sign', 'verify'],
            'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e' => 'AQAB',
            'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);
    }

    private function getKey3(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'use' => 'sig',
            'key_ops' => ['sign'],
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);
    }

    private function getKey4(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'alg' => 'PS512',
            'key_ops' => ['encrypt', 'decrypt'],
            'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e' => 'AQAB',
            'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);
    }

    private function getKey5(): JWK
    {
        return new JWK([
            'kty' => 'RSA',
            'alg' => 'PS512',
            'use' => 'sig',
            'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e' => 'AQAB',
            'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);
    }

    private function getKeyset(): JWKSet
    {
        return new JWKSet([$this->getKey1(), $this->getKey2()]);
    }

    private function getPublicKeySet(): JWKSet
    {
        $keys = ['keys' => [
            [
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=',
                'e' => 'AQAB',
            ],
            [
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'rI67uHIDWDgCy_Ut-FhhjTCkEcqzoO80IRgdpk_fJHlDmXhMTJKPizxbIEMs0wRHRZpwH-4D20thpnQB5Mgx6-XM9kOvcYpHSdcYME77BwX6uQG-hw2w77NOhYiCSZCLzx-5ld5Wjy0dympL-ExqQw-wrWipMX7NQhIbJqVbZ18=',
                'e' => 'AQAB',
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

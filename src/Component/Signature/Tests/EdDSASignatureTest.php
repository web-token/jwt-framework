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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\JWS;

/**
 * @group EdDSA
 * @group Unit
 */
class EdDSASignatureTest extends SignatureTest
{
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEdDSAVerifyAlgorithm()
    {
        $key = JWK::create([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $eddsa = new EdDSA();
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64Url::decode('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg');

        $result = $eddsa->verify($key, $input, $signature);

        self::assertTrue($result);
    }

    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEdDSASignAndVerifyAlgorithm()
    {
        $key = JWK::create([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $header = ['alg' => 'EdDSA'];
        $input = Base64Url::decode('RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc');

        $jwsBuilder = $this->getJWSBuilderFactory()->create(['EdDSA']);
        $jwsVerifier = $this->getJWSVerifierFactory()->create(['EdDSA']);
        $jws = $jwsBuilder
            ->create()->withPayload($input)
            ->addSignature($key, $header)
            ->build();

        $jws = $this->getJWSSerializerManager()->serialize('jws_compact', $jws, 0);

        self::assertEquals('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg', $jws);

        $loaded = $this->getJWSSerializerManager()->unserialize($jws);

        self::assertInstanceOf(JWS::class, $loaded);
        self::assertEquals(1, $loaded->countSignatures());
        self::assertTrue($jwsVerifier->verifyWithKey($loaded, $key, 0));
    }
}

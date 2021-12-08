<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature\Algorithm;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class EdDSASignatureTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.5
     *
     * @test
     */
    public function edDSAVerifyAlgorithm(): void
    {
        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $eddsa = new EdDSA();
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64UrlSafe::decode(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
        );

        static::assertTrue($eddsa->verify($key, $input, $signature));
    }

    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.5
     *
     * @test
     */
    public function edDSASignAndVerifyAlgorithm(): void
    {
        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $header = [
            'alg' => 'EdDSA',
        ];
        $input = 'Example of Ed25519 signing'; // Corresponds to "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new EdDSA()]));
        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new EdDSA()]));
        $jws = $jwsBuilder
            ->create()
            ->withPayload($input)
            ->addSignature($key, $header)
            ->build()
        ;

        static::assertTrue($jwsVerifier->verifyWithKey($jws, $key, 0));
    }
}

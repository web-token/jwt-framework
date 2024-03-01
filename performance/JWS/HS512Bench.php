<?php

declare(strict_types=1);

namespace Jose\Performance\JWS;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(4096)
 * @Groups({"JWS", "hmac", "HS512"})
 */
final class HS512Bench extends SignatureBench
{
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'HS512',
            ],
        ];
    }

    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJIUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.1iIN1THXoEvVr6OiIZ2jTqAsmTF0UAut_cZ6GCy31zHc66MZmfo_0uAYEoVvz1IpfC--ZPSocgY8ImtCNfDVRQ',
            ],
        ];
    }

    public function dataVerify(): array
    {
        return [
            [
                'signature' => '1iIN1THXoEvVr6OiIZ2jTqAsmTF0UAut_cZ6GCy31zHc66MZmfo_0uAYEoVvz1IpfC--ZPSocgY8ImtCNfDVRQ',
            ],
        ];
    }

    #[Override]
    protected function getAlgorithm(): SignatureAlgorithm
    {
        return $this->getSignatureAlgorithmsManager()
            ->get('HS512')
        ;
    }

    #[Override]
    protected function getInput(): string
    {
        return 'eyJhbGciOiJIUzUxMiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
    }

    #[Override]
    protected function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'k' => 'uRlFc5ToCUJtMLBi5eMrMT-k1rEytzm7quHuadKnU5Vvj6_97BtJprASN3s7eMWNQrAd9MRxpk_Du54SYAVutw',
        ]);
    }

    #[Override]
    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey();
    }
}

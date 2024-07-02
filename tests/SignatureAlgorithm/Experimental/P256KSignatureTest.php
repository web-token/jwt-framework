<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\Experimental;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Experimental\Signature\ES256K;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class P256KSignatureTest extends TestCase
{
    #[Test]
    public function es256KVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertTrue($algorithm->verify($key, $data, hex2bin(
            '9c75b9d171d9690a37f2474d4bfab5c234911cb150950ea5cbfc9aedda5ec360725cc47978de95b4efb2a3ed617c7b36b1cd0a26b536662a79d0f3ae873a7924'
        )));
    }

    #[Test]
    public function es256KSignAndVerify(): void
    {
        $key = $this->getKey();
        $algorithm = new ES256K();
        $data = 'Hello';

        static::assertSame('ES256K', $algorithm->name());

        $signature = $algorithm->sign($key, $data);

        static::assertTrue($algorithm->verify($key, $data, $signature));
    }

    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'secp256k1',
            'd' => Base64UrlSafe::encodeUnpadded(
                hex2bin('D1592A94BBB9B5D94CDC425FC7DA80B6A47863AE973A9D581FD9D8F29690B659')
            ),
            'x' => Base64UrlSafe::encodeUnpadded(
                hex2bin('4B4DF318DE05BB8F3A115BF337F9BCBC55CA14B917B46BCB557D3C9A158D4BE0')
            ),
            'y' => Base64UrlSafe::encodeUnpadded(
                hex2bin('627EB75731A8BBEBC7D9A3C57EC4D7DA2CBA6D2A28E7F45134921861FE1CF5D9')
            ),
        ]);
    }
}

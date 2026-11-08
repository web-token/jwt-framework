<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use function time;

/**
 * @internal
 */
final class JWSLoaderFactoryCriticalHeaderParameterTest extends SignatureTestCase
{
    #[Test]
    public function aLoaderWithoutHeaderCheckersRefusesACriticalHeaderParameterItDoesNotCheck(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
        $jws = $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload('Live long and prosper.')
            ->addSignature($key, [
                'alg' => 'HS256',
                'crit' => ['exp'],
                'exp' => time() + 3600,
            ])
            ->build();
        $token = $this->getJWSSerializerManager()
            ->serialize('jws_compact', $jws, 0);
        $loader = $this->getJWSLoaderFactory()
            ->create(['jws_compact'], ['HS256']);

        try {
            $loader->loadAndVerify($token, $key);
        } catch (InvalidTokenException $exception) {
            $previous = $exception->getPrevious();
            static::assertInstanceOf(InvalidHeaderException::class, $previous);
            static::assertSame(
                'One or more header parameters are marked as critical, but they are missing or have not been checked: exp.',
                $previous->getMessage()
            );

            return;
        }

        static::fail('The token has been verified.');
    }
}

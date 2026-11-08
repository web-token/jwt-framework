<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use function time;

/**
 * @internal
 */
final class JWELoaderFactoryCriticalHeaderParameterTest extends EncryptionTestCase
{
    #[Test]
    public function aLoaderWithoutHeaderCheckersRefusesACriticalHeaderParameterItDoesNotCheck(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'GawgguFyGrWKav7AX4VKUg-rT8-fUCwF0SRfTjBNy3w',
        ]);
        $jwe = $this->getJWEBuilderFactory()
            ->create(['A256KW', 'A256GCM'])
            ->create()
            ->withPayload('Live long and prosper.')
            ->withSharedProtectedHeader([
                'alg' => 'A256KW',
                'enc' => 'A256GCM',
                'crit' => ['exp'],
                'exp' => time() + 3600,
            ])
            ->addRecipient($key)
            ->build();
        $token = $this->getJWESerializerManager()
            ->serialize('jwe_compact', $jwe, 0);
        $loader = $this->getJWELoaderFactory()
            ->create(['jwe_compact'], ['A256KW', 'A256GCM']);

        try {
            $loader->loadAndDecrypt($token, $key);
        } catch (InvalidTokenException $exception) {
            $previous = $exception->getPrevious();
            static::assertInstanceOf(InvalidHeaderException::class, $previous);
            static::assertSame(
                'One or more header parameters are marked as critical, but they are missing or have not been checked: exp.',
                $previous->getMessage()
            );

            return;
        }

        static::fail('The token has been decrypted.');
    }
}

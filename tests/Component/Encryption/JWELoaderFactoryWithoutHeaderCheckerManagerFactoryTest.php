<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class JWELoaderFactoryWithoutHeaderCheckerManagerFactoryTest extends EncryptionTestCase
{
    #[Test]
    public function aFactoryWithoutHeaderCheckerManagerFactoryIsDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(function (): void {
            new JWELoaderFactory($this->getJWESerializerManagerFactory(), $this->getJWEDecrypterFactory(), null);
        });

        static::assertSame([
            'Since web-token/jwt-library 4.3.0: Creating a "Jose\\Component\\Encryption\\JWELoaderFactory" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "Jose\\Component\\Checker\\HeaderCheckerManagerFactory" that has the "Jose\\Component\\Encryption\\JWETokenSupport" token type support.',
        ], $deprecations);
    }

    #[Test]
    public function aFactoryWithAHeaderCheckerManagerFactoryIsNotDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(function (): void {
            new JWELoaderFactory($this->getJWESerializerManagerFactory(), $this->getJWEDecrypterFactory(), new HeaderCheckerManagerFactory());
        });

        static::assertSame([], $deprecations);
    }

    /**
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}

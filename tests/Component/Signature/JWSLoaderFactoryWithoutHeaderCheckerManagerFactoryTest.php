<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Signature\JWSLoaderFactory;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class JWSLoaderFactoryWithoutHeaderCheckerManagerFactoryTest extends SignatureTestCase
{
    #[Test]
    public function aFactoryWithoutHeaderCheckerManagerFactoryIsDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(function (): void {
            new JWSLoaderFactory($this->getJWSSerializerManagerFactory(), $this->getJWSVerifierFactory(), null);
        });

        static::assertSame([
            'Since web-token/jwt-library 4.3.0: Creating a "Jose\\Component\\Signature\\JWSLoaderFactory" without a header checker manager factory is deprecated and will not be possible in 5.0.0: the loaders it creates check no header parameter, not even those listed in "crit". Pass a "Jose\\Component\\Checker\\HeaderCheckerManagerFactory".',
        ], $deprecations);
    }

    #[Test]
    public function aFactoryWithAHeaderCheckerManagerFactoryIsNotDeprecated(): void
    {
        $deprecations = $this->collectDeprecations(function (): void {
            new JWSLoaderFactory($this->getJWSSerializerManagerFactory(), $this->getJWSVerifierFactory(), new HeaderCheckerManagerFactory());
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

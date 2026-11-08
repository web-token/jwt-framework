<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Closure;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Tests\Bundle\JoseFramework\IsolatedKernel;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Filesystem\Filesystem;
use function array_filter;
use function array_values;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function str_contains;
use const E_USER_DEPRECATED;

/**
 * @internal
 */
final class AliasCollisionTest extends TestCase
{
    private ?IsolatedKernel $kernel = null;

    protected function tearDown(): void
    {
        if ($this->kernel !== null) {
            $this->kernel->shutdown();
            (new Filesystem())->remove($this->kernel->getVarDir());
            $this->kernel = null;
        }
        parent::tearDown();
    }

    #[Test]
    public function anApplicationCheckerTaggedWithAnAliasOfTheBundleIsReported(): void
    {
        $deprecations = $this->bootKernel(static function (ContainerBuilder $container): void {
            $container->register('app.protected_exp_header_checker', ExpirationTimeChecker::class)
                ->setArguments([
                    '$clock' => new Reference(ClockInterface::class),
                    '$protectedHeaderOnly' => true,
                ])
                ->addTag('jose.checker.header', [
                    'alias' => 'exp',
                ]);
            $container->loadFromExtension('jose', [
                'checkers' => [
                    'headers' => [
                        'api' => [
                            'headers' => ['exp'],
                        ],
                    ],
                ],
            ]);
        });

        static::assertSame([sprintf(
            'Since web-token/jwt-framework 4.3.0: The services "app.protected_exp_header_checker" and "%s" are both tagged "jose.checker.header" with the alias "exp": "%s" replaces "app.protected_exp_header_checker". Sharing an alias between two services is deprecated and will not be possible in 5.0.0; give each service an alias of its own.',
            ExpirationTimeChecker::class,
            ExpirationTimeChecker::class
        )], $deprecations);

        $manager = $this->kernel?->getContainer()
            ->get('jose.header_checker.api');
        static::assertInstanceOf(HeaderCheckerManager::class, $manager);
        $checker = $manager->getCheckers()['exp'] ?? null;
        static::assertInstanceOf(ExpirationTimeChecker::class, $checker);
        static::assertFalse($checker->protectedHeaderOnly());
    }

    #[Test]
    public function theServicesOfTheBundleUseEachAliasOnce(): void
    {
        $deprecations = $this->bootKernel(static function (ContainerBuilder $container): void {
            $container->loadFromExtension('jose', [
                'checkers' => [
                    'claims' => [
                        'api' => [
                            'claims' => ['exp', 'iat', 'nbf'],
                        ],
                    ],
                    'headers' => [
                        'api' => [
                            'headers' => ['exp', 'iat', 'nbf'],
                            'typ' => ['at+jwt'],
                        ],
                        'id_token' => [
                            'headers' => [],
                            'typ' => ['JWT'],
                        ],
                    ],
                ],
            ]);
        });

        static::assertSame([], $deprecations);
    }

    /**
     * Boots a kernel whose container is compiled for this test only, and returns the deprecations about tag aliases
     * that the compilation triggered.
     *
     * @param Closure(ContainerBuilder): void $configure
     *
     * @return list<string>
     */
    private function bootKernel(Closure $configure): array
    {
        $this->kernel = new IsolatedKernel($configure);
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $this->kernel->boot();
        } finally {
            restore_error_handler();
        }

        return array_values(array_filter(
            $deprecations,
            static fn (string $deprecation): bool => str_contains($deprecation, ' with the alias ')
        ));
    }
}

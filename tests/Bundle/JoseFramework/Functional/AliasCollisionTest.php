<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Closure;
use InvalidArgumentException;
use Jose\Component\Checker\ClaimCheckerManagerInterface;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Tests\Bundle\JoseFramework\IsolatedKernel;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Filesystem\Filesystem;
use function sprintf;

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
    public function anApplicationCheckerTaggedWithAnAliasOfTheBundleIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The services "app.protected_exp_header_checker" and "%s" are both tagged "jose.checker.header" with the alias "exp", but an alias names a single service. Give each service an alias of its own.',
            ExpirationTimeChecker::class
        ));

        $this->bootKernel(static function (ContainerBuilder $container): void {
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
    }

    #[Test]
    public function theServicesOfTheBundleUseEachAliasOnce(): void
    {
        $this->bootKernel(static function (ContainerBuilder $container): void {
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

        $container = $this->kernel?->getContainer();
        static::assertInstanceOf(ClaimCheckerManagerInterface::class, $container?->get('jose.claim_checker.api'));
        static::assertInstanceOf(HeaderCheckerManagerInterface::class, $container?->get('jose.header_checker.api'));
        static::assertInstanceOf(HeaderCheckerManagerInterface::class, $container?->get('jose.header_checker.id_token'));
    }

    /**
     * Boots a kernel whose container is compiled for this test only.
     *
     * @param Closure(ContainerBuilder): void $configure
     */
    private function bootKernel(Closure $configure): void
    {
        $this->kernel = new IsolatedKernel($configure);
        $this->kernel->boot();
    }
}

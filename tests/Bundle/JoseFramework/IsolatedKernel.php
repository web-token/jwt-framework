<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework;

use Closure;
use Jose\Bundle\JoseFramework\JoseFrameworkBundle;
use Override;
use Psr\Clock\ClockInterface;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\HttpKernel\Kernel;
use function bin2hex;
use function random_bytes;
use function sys_get_temp_dir;

/**
 * Kernel configured by a closure, whose container is compiled in a directory of its own at the first boot. A test can
 * then see what the compilation reports, which the shared cache of AppKernel hides once it is warm. The test removes
 * the directory returned by getVarDir().
 */
final class IsolatedKernel extends Kernel
{
    private readonly string $varDir;

    /**
     * @param Closure(ContainerBuilder): void $configure
     */
    public function __construct(
        private readonly Closure $configure
    ) {
        $this->varDir = sys_get_temp_dir() . '/jose-isolated-kernel-' . bin2hex(random_bytes(8));
        parent::__construct('isolated', false);
    }

    /**
     * @return BundleInterface[]
     */
    #[Override]
    public function registerBundles(): array
    {
        return [new FrameworkBundle(), new JoseFrameworkBundle()];
    }

    #[Override]
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'test' => true,
                'secret' => 'test',
            ]);
            $container->register(ClockInterface::class, NativeClock::class);
            ($this->configure)($container);
        });
    }

    #[Override]
    public function getCacheDir(): string
    {
        return $this->varDir . '/cache';
    }

    #[Override]
    public function getLogDir(): string
    {
        return $this->varDir . '/log';
    }

    public function getVarDir(): string
    {
        return $this->varDir;
    }
}

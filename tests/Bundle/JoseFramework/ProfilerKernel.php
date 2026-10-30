<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework;

use Jose\Bundle\JoseFramework\JoseFrameworkBundle;
use Override;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\HttpKernel\Kernel;

/**
 * Kernel running in debug mode with the profiler enabled, as an application does in its dev environment.
 *
 * The bundle only registers its data collectors when kernel.debug is true, which AppKernel never is. The environment
 * is fixed so that this kernel never shares its cache directory with AppKernel.
 */
final class ProfilerKernel extends Kernel
{
    public function __construct()
    {
        parent::__construct('profiler', true);
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
        $loader->load(__DIR__ . '/config/config_profiler.yml');
    }
}

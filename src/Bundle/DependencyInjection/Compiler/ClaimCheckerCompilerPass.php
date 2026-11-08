<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Override;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final readonly class ClaimCheckerCompilerPass implements CompilerPassInterface
{
    use TaggedServiceAliases;

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(ClaimCheckerManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(ClaimCheckerManagerFactory::class);
        $this->addTaggedServices($container, $definition, 'jose.checker.claim', 'claim checker');
    }
}

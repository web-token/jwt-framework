<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Component\Core\AlgorithmManagerFactory;
use Override;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final readonly class AlgorithmCompilerPass implements CompilerPassInterface
{
    use TaggedServiceAliases;

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(AlgorithmManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(AlgorithmManagerFactory::class);
        $this->addTaggedServices($container, $definition, 'jose.algorithm', 'algorithm');
    }
}

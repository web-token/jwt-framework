<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Override;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final readonly class HeaderCheckerCompilerPass implements CompilerPassInterface
{
    use TaggedServiceAliases;

    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(HeaderCheckerManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(HeaderCheckerManagerFactory::class);
        $this->addTaggedServices($container, $definition, 'jose.checker.header', 'header checker');
        $this->addTokenType($definition, $container);
    }

    private function addTokenType(Definition $definition, ContainerBuilder $container): void
    {
        $taggedHeaderCheckerServices = $container->findTaggedServiceIds('jose.checker.token_type');
        foreach ($taggedHeaderCheckerServices as $id => $tags) {
            $definition->addMethodCall('addTokenTypeSupport', [new Reference($id)]);
        }
    }
}

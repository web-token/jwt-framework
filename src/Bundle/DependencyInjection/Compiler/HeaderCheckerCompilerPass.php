<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final class HeaderCheckerCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(HeaderCheckerManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(HeaderCheckerManagerFactory::class);
        $this->addHeaderCheckers($definition, $container);
        $this->addTokenType($definition, $container);
    }

    private function addHeaderCheckers(Definition $definition, ContainerBuilder $container): void
    {
        $taggedHeaderCheckerServices = $container->findTaggedServiceIds('jose.checker.header');
        foreach ($taggedHeaderCheckerServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (! isset($attributes['alias'])) {
                    throw new InvalidArgumentException(sprintf(
                        'The header checker "%s" does not have any "alias" attribute.',
                        $id
                    ));
                }
                $definition->addMethodCall('add', [$attributes['alias'], new Reference($id)]);
            }
        }
    }

    private function addTokenType(Definition $definition, ContainerBuilder $container): void
    {
        $taggedHeaderCheckerServices = $container->findTaggedServiceIds('jose.checker.token_type');
        foreach ($taggedHeaderCheckerServices as $id => $tags) {
            $definition->addMethodCall('addTokenTypeSupport', [new Reference($id)]);
        }
    }
}

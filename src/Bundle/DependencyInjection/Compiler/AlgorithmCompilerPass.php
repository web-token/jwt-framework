<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class AlgorithmCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(AlgorithmManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(AlgorithmManagerFactory::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.algorithm');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (! isset($attributes['alias'])) {
                    throw new InvalidArgumentException(sprintf(
                        'The algorithm "%s" does not have any "alias" attribute.',
                        $id
                    ));
                }
                $definition->addMethodCall('add', [$attributes['alias'], new Reference($id)]);
            }
        }
    }
}

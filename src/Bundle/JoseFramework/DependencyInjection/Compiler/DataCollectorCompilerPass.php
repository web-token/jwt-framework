<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\DataCollector\JoseCollector;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class DataCollectorCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(JoseCollector::class)) {
            return;
        }

        $definition = $container->getDefinition(JoseCollector::class);
        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.data_collector');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}

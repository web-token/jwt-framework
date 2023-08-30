<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class CompressionMethodCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(CompressionMethodManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(CompressionMethodManagerFactory::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.compression_method');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            foreach ($tags as $attributes) {
                if (! isset($attributes['alias'])) {
                    throw new InvalidArgumentException(sprintf(
                        'The compression method "%s" does not have any "alias" attribute.',
                        $id
                    ));
                }
                $definition->addMethodCall('add', [$attributes['alias'], new Reference($id)]);
            }
        }
    }
}

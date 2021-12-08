<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class EncryptionSerializerCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(JWESerializerManagerFactory::class)) {
            return;
        }

        $definition = $container->getDefinition(JWESerializerManagerFactory::class);

        $taggedAlgorithmServices = $container->findTaggedServiceIds('jose.jwe.serializer');
        foreach ($taggedAlgorithmServices as $id => $tags) {
            $definition->addMethodCall('add', [new Reference($id)]);
        }
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Jose\Bundle\JoseFramework\DataCollector\KeyCollector;
use Override;
use Symfony\Component\DependencyInjection\Argument\ServiceClosureArgument;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The keys and key sets are given to the collector as closures, so that creating the profiler does not create them.
 */
final readonly class KeyCollectorCompilerPass implements CompilerPassInterface
{
    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(KeyCollector::class)) {
            return;
        }

        $definition = $container->getDefinition(KeyCollector::class);

        $services = [
            'addLazyJWK' => 'jose.jwk',
            'addLazyJWKSet' => 'jose.jwkset',
        ];
        foreach ($services as $method => $tag) {
            $this->collectServices($method, $tag, $definition, $container);
        }
    }

    private function collectServices(
        string $method,
        string $tag,
        Definition $definition,
        ContainerBuilder $container
    ): void {
        $taggedJWSServices = $container->findTaggedServiceIds($tag);
        foreach ($taggedJWSServices as $id => $tags) {
            $definition->addMethodCall($method, [$id, new ServiceClosureArgument(new Reference($id))]);
        }
    }
}

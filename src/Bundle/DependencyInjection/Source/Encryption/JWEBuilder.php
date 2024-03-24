<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Encryption;

use Jose\Bundle\JoseFramework\Services\JWEBuilderFactory;
use Jose\Component\Encryption\JWEBuilder as JWEBuilderService;
use Override;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

final readonly class JWEBuilder extends AbstractEncryptionSource
{
    #[Override]
    public function name(): string
    {
        return 'builders';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jwe_builder.%s', $name);
            $definition = new Definition(JWEBuilderService::class);
            $definition
                ->setFactory([new Reference(JWEBuilderFactory::class), 'create'])
                ->setArguments([$itemConfig['encryption_algorithms']])
                ->addTag('jose.jwe_builder')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, JWEBuilderService::class, $name . 'JweBuilder');
        }
    }
}

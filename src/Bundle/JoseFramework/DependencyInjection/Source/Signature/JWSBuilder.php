<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature;

use Jose\Bundle\JoseFramework\Services\JWSBuilderFactory;
use Jose\Component\Signature\JWSBuilder as JWSBuilderService;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JWSBuilder extends AbstractSignatureSource
{
    public function name(): string
    {
        return 'builders';
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.jws_builder.%s', $name);
            $definition = new Definition(JWSBuilderService::class);
            $definition
                ->setFactory([new Reference(JWSBuilderFactory::class), 'create'])
                ->setArguments([$itemConfig['signature_algorithms']])
                ->addTag('jose.jws_builder')
                ->setPublic($itemConfig['is_public'])
            ;
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
        }
    }
}

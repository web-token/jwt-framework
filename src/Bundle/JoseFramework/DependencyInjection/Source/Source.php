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

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

interface Source
{
    public function name(): string;

    public function load(array $configs, ContainerBuilder $container): void;

    public function getNodeDefinition(NodeDefinition $node): void;

    public function prepend(ContainerBuilder $container, array $config): array;
}

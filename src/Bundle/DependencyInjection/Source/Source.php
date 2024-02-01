<?php

declare(strict_types=1);

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

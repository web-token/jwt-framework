<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\JWKSource;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;

interface JWKSource
{
    /**
     * Creates the JWK, registers it and returns its id.
     *
     * @param ContainerBuilder $container A ContainerBuilder instance
     * @param string $type The type of the service
     * @param string $id The id of the service
     * @param array<string, mixed> $config An array of configuration
     */
    public function create(ContainerBuilder $container, string $type, string $id, array $config): void;

    /**
     * Returns the key for the Key Source configuration.
     */
    public function getKey(): string;

    /**
     * Adds configuration nodes for this service.
     */
    public function addConfiguration(NodeDefinition $builder): void;
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use function count;

final class JoseFrameworkExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @param Source[] $sources
     */
    public function __construct(
        private readonly string $alias,
        private readonly array $sources
    ) {
    }

    public function getAlias(): string
    {
        return $this->alias;
    }

    /**
     * @param array<array> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $processor = new Processor();
        $config = $processor->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->sources as $source) {
            $source->load($config, $container);
        }
    }

    public function getConfiguration(array $configs, ContainerBuilder $container): Configuration
    {
        return new Configuration($this->getAlias(), $this->sources);
    }

    public function prepend(ContainerBuilder $container): void
    {
        $configs = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration($this->getConfiguration($configs, $container), $configs);

        foreach ($this->sources as $source) {
            $result = $source->prepend($container, $config);
            if (count($result) !== 0) {
                $container->prependExtensionConfig($this->getAlias(), $result);
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManager;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Checker\TypeChecker;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use function count;
use function is_array;
use function sprintf;

/**
 * Declares the header checker managers of the "jose.checkers.headers" configuration.
 *
 * Besides the list of checker aliases, each manager may declare the media types accepted for the "typ" header
 * (RFC 8725 section 3.11). A dedicated TypeChecker service is then registered with the alias "typ.<manager name>"
 * and added to the manager.
 */
final readonly class HeaderChecker implements Source
{
    #[Override]
    public function name(): string
    {
        return 'headers';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.header_checker.%s', $name);
            $aliases = $itemConfig['headers'];
            $types = $itemConfig['typ'];
            if (is_array($types) && count($types) !== 0) {
                $aliases[] = $this->registerTypeChecker(sprintf('typ.%s', $name), array_values($types), $container);
            }
            $definition = new Definition(HeaderCheckerManager::class);
            $definition
                ->setFactory([new Reference(HeaderCheckerManagerFactory::class), 'create'])
                ->setArguments([$aliases])
                ->addTag('jose.header_checker_manager')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument(
                $service_id,
                HeaderCheckerManager::class,
                $name . 'HeaderCheckerManager'
            );
            $container->registerAliasForArgument(
                $service_id,
                HeaderCheckerManagerInterface::class,
                $name . 'HeaderCheckerManager'
            );
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node
            ->children()
            ->arrayNode($this->name())
            ->treatFalseLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->arrayNode('headers')
            ->info('A list of header aliases to be set in the claim checker.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('typ')
            ->info(
                'The media types accepted for the "typ" header parameter (e.g. "at+jwt"). When set, a "typ" checker is added to the manager.'
            )
            ->beforeNormalization()
            ->ifString()
            ->then(static fn (string $type): array => [$type])
            ->end()
            ->scalarPrototype()
            ->cannotBeEmpty()
            ->end()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the claim checker.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    #[Override]
    public function prepend(ContainerBuilder $container, array $config): array
    {
        return [];
    }

    /**
     * @param non-empty-list<mixed> $types
     *
     * @return string the alias under which the checker is registered
     */
    private function registerTypeChecker(string $alias, array $types, ContainerBuilder $container): string
    {
        $definition = new Definition(TypeChecker::class);
        $definition
            ->setArguments([$types])
            ->addTag('jose.checker.header', [
                'alias' => $alias,
            ])
            ->setPublic(false);
        $container->setDefinition(sprintf('jose.checker.header.%s', $alias), $definition);

        return $alias;
    }
}

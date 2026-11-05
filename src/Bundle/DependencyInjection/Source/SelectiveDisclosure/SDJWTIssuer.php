<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\SelectiveDisclosure;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\SDJWTIssuerFactory;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTIssuer as SDJWTIssuerService;
use Jose\SelectiveDisclosure\SDJWTIssuerInterface;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use function sprintf;

final readonly class SDJWTIssuer implements Source
{
    #[Override]
    public function name(): string
    {
        return 'issuers';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.sd_jwt_issuer.%s', $name);
            $definition = new Definition(SDJWTIssuerService::class);
            $definition
                ->setFactory([new Reference(SDJWTIssuerFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['signature_algorithms'],
                    $itemConfig['hash_algorithm'],
                    $itemConfig['minimum_decoy_digests'],
                    $itemConfig['maximum_decoy_digests'],
                ])
                ->addTag('jose.sd_jwt_issuer')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, SDJWTIssuerService::class, $name . 'SdJwtIssuer');
            $container->registerAliasForArgument($service_id, SDJWTIssuerInterface::class, $name . 'SdJwtIssuer');
        }
    }

    #[Override]
    public function getNodeDefinition(NodeDefinition $node): void
    {
        $node->children()
            ->arrayNode($this->name())
            ->treatNullLike([])
            ->treatFalseLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->children()
            ->booleanNode('is_public')
            ->info('If true, the service will be public, else private.')
            ->defaultTrue()
            ->end()
            ->arrayNode('signature_algorithms')
            ->info('A list of signature algorithm aliases.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->enumNode('hash_algorithm')
            ->info('The IANA name of the hash function of the digests.')
            ->values(SDJWT::hashAlgorithms())
            ->defaultValue(SDJWT::DEFAULT_HASH_ALGORITHM)
            ->end()
            ->integerNode('minimum_decoy_digests')
            ->info(
                'The minimum number of decoy digests added to each object and array that has selectively disclosable claims.'
            )
            ->min(0)
            ->defaultValue(0)
            ->end()
            ->integerNode('maximum_decoy_digests')
            ->info('The maximum number of decoy digests. The minimum when not set.')
            ->min(0)
            ->defaultNull()
            ->end()
            ->arrayNode('tags')
            ->info('A list of tags to be associated to the service.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->variablePrototype()
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
}

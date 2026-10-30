<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Source\SelectiveDisclosure;

use Jose\Bundle\JoseFramework\DependencyInjection\Source\Source;
use Jose\Bundle\JoseFramework\Services\SDJWTVerifierFactory;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTVerifier as SDJWTVerifierService;
use Jose\SelectiveDisclosure\SDJWTVerifierInterface;
use Override;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use function sprintf;

final readonly class SDJWTVerifier implements Source
{
    #[Override]
    public function name(): string
    {
        return 'verifiers';
    }

    #[Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        foreach ($configs[$this->name()] as $name => $itemConfig) {
            $service_id = sprintf('jose.sd_jwt_verifier.%s', $name);
            $definition = new Definition(SDJWTVerifierService::class);
            $definition
                ->setFactory([new Reference(SDJWTVerifierFactory::class), 'create'])
                ->setArguments([
                    $itemConfig['signature_algorithms'],
                    $itemConfig['header_checkers'],
                    $itemConfig['key_binding_signature_algorithms'],
                    $itemConfig['key_binding_header_checkers'],
                    $itemConfig['claim_checkers'],
                    $itemConfig['mandatory_claims'],
                    $itemConfig['hash_algorithms'],
                    $itemConfig['key_binding_max_age'],
                    $itemConfig['allowed_time_drift'],
                ])
                ->addTag('jose.sd_jwt_verifier')
                ->setPublic($itemConfig['is_public']);
            foreach ($itemConfig['tags'] as $id => $attributes) {
                $definition->addTag($id, $attributes);
            }
            $container->setDefinition($service_id, $definition);
            $container->registerAliasForArgument($service_id, SDJWTVerifierService::class, $name . 'SdJwtVerifier');
            $container->registerAliasForArgument($service_id, SDJWTVerifierInterface::class, $name . 'SdJwtVerifier');
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
            ->info('A list of signature algorithm aliases, for the Issuer-signed JWTs.')
            ->useAttributeAsKey('name')
            ->isRequired()
            ->requiresAtLeastOneElement()
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('header_checkers')
            ->info('A list of header checker aliases, for the Issuer-signed JWTs.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('key_binding_signature_algorithms')
            ->info(
                'A list of signature algorithm aliases, for the Key Binding JWTs. Those of the Issuer-signed JWTs when empty.'
            )
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('key_binding_header_checkers')
            ->info('A list of header checker aliases, for the Key Binding JWTs.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('claim_checkers')
            ->info('A list of claim checker aliases, for the processed payloads.')
            ->useAttributeAsKey('name')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('mandatory_claims')
            ->info('A list of claims the processed payloads must contain.')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('hash_algorithms')
            ->info('The IANA names of the accepted hash functions of the digests. All the supported ones when empty.')
            ->treatNullLike([])
            ->treatFalseLike([])
            ->enumPrototype()
            ->values(SDJWT::hashAlgorithms())
            ->end()
            ->end()
            ->integerNode('key_binding_max_age')
            ->info('The maximum age of a Key Binding JWT, in seconds.')
            ->min(0)
            ->defaultValue(300)
            ->end()
            ->integerNode('allowed_time_drift')
            ->info('The drift allowed between the clocks, in seconds.')
            ->min(0)
            ->defaultValue(0)
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

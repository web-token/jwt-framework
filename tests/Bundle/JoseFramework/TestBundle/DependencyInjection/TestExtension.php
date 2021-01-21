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

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\DependencyInjection;

use Jose\Bundle\JoseFramework\Helper\ConfigurationHelper;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * Class TestExtension.
 */
class TestExtension extends Extension implements PrependExtensionInterface
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.php');
    }

    public function prepend(ContainerBuilder $container): void
    {
        ConfigurationHelper::addKey($container, 'jwk2', 'jwk', [
            'value' => '{"kty":"oct","k":"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g"}',
            'is_public' => true,
        ]);
        ConfigurationHelper::addKeyset($container, 'jwkset2', 'jwkset', [
            'value' => '{"keys":[{"kty":"oct","k":"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g"},{"kty":"oct","k":"bwIAv5Nn-fo8p4LCEvM4IR9eLXgzJRs8jXCLb3xR0tDJGiZ46KheO4ip6htFKyN2aqJqlNi9-7hB6I1aLLy1IRT9-vcBoCSGu977cNAUuRLkRp7vo8s6MsxhB8WvQBDRZghV7jIYaune-3vbE7iDU2AESr8BUtorckLoO9uW__fIabaa3hJMMQIHCzYQbJKZvlCRCKWMk2H_zuS4JeDFTvyZH1skJYF_TET1DrCZHMPicw-Yk3_m2P-ilC-yidPPoVzeU8Jj3tQ6gtX3975qiQW7pt2qbgjKAuq2wsz_9hxLBtMB5rQPafFoxop7O4BklvZ9-ECcK6dfI2CAx9_tjQ"}]}',
            'is_public' => true,
        ]);
        ConfigurationHelper::addKeyUri($container, 'jwkset2', [
            'id' => 'jose.key_set.jwkset2',
            'path' => '/2.jwkset',
        ]);
        ConfigurationHelper::addClaimChecker($container, 'checker2', ['exp', 'iat', 'nbf', 'custom_checker'], true);
        ConfigurationHelper::addHeaderChecker($container, 'checker2', ['custom_checker'], true);
        ConfigurationHelper::addJWSBuilder($container, 'builder2', ['RS512', 'HS512', 'ES512'], true);
        ConfigurationHelper::addJWSVerifier($container, 'loader2', ['RS512', 'HS512', 'ES512'], true);
        ConfigurationHelper::addJWSSerializer($container, 'jws_serializer2', ['jws_compact', 'jws_json_flattened', 'jws_json_general'], true);
        ConfigurationHelper::addJWSLoader($container, 'jws_loader2', ['jws_compact'], ['HS512'], [], true);
        ConfigurationHelper::addJWEBuilder($container, 'builder2', ['RSA-OAEP-256'], ['A128GCM'], ['DEF'], true);
        ConfigurationHelper::addJWEDecrypter($container, 'loader2', ['RSA-OAEP-256'], ['A128GCM'], ['DEF'], true);
        ConfigurationHelper::addJWESerializer($container, 'jwe_serializer2', ['jwe_compact', 'jwe_json_flattened', 'jwe_json_general'], true);
        ConfigurationHelper::addJWELoader($container, 'jwe_loader2', ['jwe_compact'], ['RSA-OAEP-256'], ['A128GCM'], ['DEF'], [], true);
        ConfigurationHelper::addNestedTokenLoader($container, 'nested_token_loader_2', ['jwe_compact'], ['RSA-OAEP'], ['A128GCM'], ['DEF'], [], ['jws_compact'], ['PS256'], [], true, []);
        ConfigurationHelper::addNestedTokenBuilder($container, 'nested_token_builder_2', ['jwe_compact'], ['RSA-OAEP'], ['A128GCM'], ['DEF'], ['jws_compact'], ['PS256'], true, []);
    }
}

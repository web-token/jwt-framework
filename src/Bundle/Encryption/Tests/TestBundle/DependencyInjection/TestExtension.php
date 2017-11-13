<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Encryption\Tests\TestBundle\DependencyInjection;

use Jose\Bundle\JoseFramework\Helper\ConfigurationHelper;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * Class TestExtension.
 */
final class TestExtension extends Extension implements PrependExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');
    }

    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        ConfigurationHelper::addJWEBuilder($container, 'builder2', ['RSA-OAEP-256'], ['A128GCM'], ['DEF'], true);
        ConfigurationHelper::addJWEDecrypter($container, 'loader2', ['RSA-OAEP-256'], ['A128GCM'], ['DEF'], [], true);
        ConfigurationHelper::addJWESerializer($container, 'jwe_serializer2', ['jwe_compact', 'jwe_json_flattened', 'jwe_json_general']);
    }
}

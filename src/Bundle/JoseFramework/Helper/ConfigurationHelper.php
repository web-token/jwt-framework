<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Helper;

use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * This helper will help you to create services configuration.
 */
final class ConfigurationHelper
{
    const BUNDLE_ALIAS = 'jose';

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $signatureAlgorithms
     * @param bool             $is_public
     */
    public static function addJWSBuilder(ContainerBuilder $container, string $name, array $signatureAlgorithms, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'builders' => [
                        $name => [
                            'is_public'            => $is_public,
                            'signature_algorithms' => $signatureAlgorithms,
                        ],
                    ],
                ],
            ],
        ];
        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $signatureAlgorithms
     * @param bool             $is_public
     */
    public static function addJWSVerifier(ContainerBuilder $container, string $name, array $signatureAlgorithms, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'verifiers' => [
                        $name => [
                            'is_public'            => $is_public,
                            'signature_algorithms' => $signatureAlgorithms,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $serializers
     * @param bool             $is_public
     */
    public static function addJWSSerializer(ContainerBuilder $container, string $name, array $serializers, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'serializers' => [
                        $name => [
                            'is_public'   => $is_public,
                            'serializers' => $serializers,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $serializers
     * @param bool             $is_public
     */
    public static function addJWESerializer(ContainerBuilder $container, string $name, array $serializers, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'serializers' => [
                        $name => [
                            'is_public'   => $is_public,
                            'serializers' => $serializers,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $claimCheckers
     * @param bool             $is_public
     */
    public static function addClaimChecker(ContainerBuilder $container, string $name, array  $claimCheckers, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'claims' => [
                        $name => [
                            'is_public' => $is_public,
                            'claims'    => $claimCheckers,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'checkers');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string[]         $headerCheckers
     * @param bool             $is_public
     */
    public static function addHeaderChecker(ContainerBuilder $container, string $name, array  $headerCheckers, bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'headers' => [
                        $name => [
                            'is_public' => $is_public,
                            'headers'   => $headerCheckers,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'checkers');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string           $type
     * @param array            $parameters
     */
    public static function addKey(ContainerBuilder $container, string $name, string $type, array  $parameters)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'keys' => [
                    $name => [
                        $type => $parameters,
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'keys');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param string           $type
     * @param array            $parameters
     */
    public static function addKeyset(ContainerBuilder $container, string $name, string $type, array  $parameters)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'key_sets' => [
                    $name => [
                        $type => $parameters,
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'key_sets');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param array            $parameters
     */
    public static function addKeyUri(ContainerBuilder $container, string $name, array $parameters)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwk_uris' => [
                    $name => $parameters,
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwk_uris');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param array            $keyEncryptionAlgorithm
     * @param array            $contentEncryptionAlgorithms
     * @param array            $compressionMethods
     * @param bool             $is_public
     */
    public static function addJWEBuilder(ContainerBuilder $container, string $name, array $keyEncryptionAlgorithm, array $contentEncryptionAlgorithms, array $compressionMethods = ['DEF'], bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'builders' => [
                        $name => [
                            'is_public'                     => $is_public,
                            'key_encryption_algorithms'     => $keyEncryptionAlgorithm,
                            'content_encryption_algorithms' => $contentEncryptionAlgorithms,
                            'compression_methods'           => $compressionMethods,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    /**
     * @param ContainerBuilder $container
     * @param string           $name
     * @param array            $keyEncryptionAlgorithm
     * @param array            $contentEncryptionAlgorithms
     * @param array            $compressionMethods
     * @param bool             $is_public
     */
    public static function addJWEDecrypter(ContainerBuilder $container, string $name, array $keyEncryptionAlgorithm, array $contentEncryptionAlgorithms, array $compressionMethods = ['DEF'], bool $is_public = true)
    {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'decrypters' => [
                        $name => [
                            'is_public'                     => $is_public,
                            'key_encryption_algorithms'     => $keyEncryptionAlgorithm,
                            'content_encryption_algorithms' => $contentEncryptionAlgorithms,
                            'compression_methods'           => $compressionMethods,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    /**
     * @param ContainerBuilder $container
     * @param array            $config
     * @param string           $element
     */
    private static function updateJoseConfiguration(ContainerBuilder $container, array $config, string $element)
    {
        $jose_config = current($container->getExtensionConfig(self::BUNDLE_ALIAS));
        if (!isset($jose_config[$element])) {
            $jose_config[$element] = [];
        }
        $jose_config[$element] = array_merge($jose_config[$element], $config[self::BUNDLE_ALIAS][$element]);
        $container->prependExtensionConfig(self::BUNDLE_ALIAS, $jose_config);
    }
}

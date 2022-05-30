<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Helper;

use function is_array;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class ConfigurationHelper
{
    final public const BUNDLE_ALIAS = 'jose';

    /**
     * @param string[] $signatureAlgorithms
     */
    public static function addJWSBuilder(
        ContainerBuilder $container,
        string $name,
        array $signatureAlgorithms,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'builders' => [
                        $name => [
                            'is_public' => $is_public,
                            'signature_algorithms' => $signatureAlgorithms,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];
        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param string[] $signatureAlgorithms
     */
    public static function addJWSVerifier(
        ContainerBuilder $container,
        string $name,
        array $signatureAlgorithms,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'verifiers' => [
                        $name => [
                            'is_public' => $is_public,
                            'signature_algorithms' => $signatureAlgorithms,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param string[] $serializers
     */
    public static function addJWSSerializer(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'serializers' => [
                        $name => [
                            'is_public' => $is_public,
                            'serializers' => $serializers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param string[] $serializers
     * @param string[] $signature_algorithms
     * @param string[] $header_checkers
     */
    public static function addJWSLoader(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        array $signature_algorithms,
        array $header_checkers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $is_public,
                            'serializers' => $serializers,
                            'signature_algorithms' => $signature_algorithms,
                            'header_checkers' => $header_checkers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jws');
    }

    /**
     * @param string[] $jwe_serializers
     * @param string[] $key_encryption_algorithms
     * @param string[] $content_encryption_algorithms
     * @param string[] $compression_methods
     * @param string[] $jwe_header_checkers
     * @param string[] $jws_serializers
     * @param string[] $signature_algorithms
     * @param string[] $jws_header_checkers
     */
    public static function addNestedTokenLoader(
        ContainerBuilder $container,
        string $name,
        array $jwe_serializers,
        array $key_encryption_algorithms,
        array $content_encryption_algorithms,
        array $compression_methods,
        array $jwe_header_checkers,
        array $jws_serializers,
        array $signature_algorithms,
        array $jws_header_checkers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'nested_token' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $is_public,
                            'jwe_serializers' => $jwe_serializers,
                            'key_encryption_algorithms' => $key_encryption_algorithms,
                            'content_encryption_algorithms' => $content_encryption_algorithms,
                            'compression_methods' => $compression_methods,
                            'jwe_header_checkers' => $jwe_header_checkers,
                            'jws_serializers' => $jws_serializers,
                            'signature_algorithms' => $signature_algorithms,
                            'jws_header_checkers' => $jws_header_checkers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'nested_token');
    }

    /**
     * @param string[] $jwe_serializers
     * @param string[] $key_encryption_algorithms
     * @param string[] $content_encryption_algorithms
     * @param string[] $compression_methods
     * @param string[] $jws_serializers
     * @param string[] $signature_algorithms
     */
    public static function addNestedTokenBuilder(
        ContainerBuilder $container,
        string $name,
        array $jwe_serializers,
        array $key_encryption_algorithms,
        array $content_encryption_algorithms,
        array $compression_methods,
        array $jws_serializers,
        array $signature_algorithms,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'nested_token' => [
                    'builders' => [
                        $name => [
                            'is_public' => $is_public,
                            'jwe_serializers' => $jwe_serializers,
                            'key_encryption_algorithms' => $key_encryption_algorithms,
                            'content_encryption_algorithms' => $content_encryption_algorithms,
                            'compression_methods' => $compression_methods,
                            'jws_serializers' => $jws_serializers,
                            'signature_algorithms' => $signature_algorithms,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'nested_token');
    }

    /**
     * @param string[] $serializers
     */
    public static function addJWESerializer(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'serializers' => [
                        $name => [
                            'is_public' => $is_public,
                            'serializers' => $serializers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    /**
     * @param string[] $serializers
     * @param string[] $key_encryption_algorithms
     * @param string[] $content_encryption_algorithms
     * @param string[] $compression_methods
     * @param string[] $header_checkers
     */
    public static function addJWELoader(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        array $key_encryption_algorithms,
        array $content_encryption_algorithms,
        array $compression_methods,
        array $header_checkers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $is_public,
                            'serializers' => $serializers,
                            'key_encryption_algorithms' => $key_encryption_algorithms,
                            'content_encryption_algorithms' => $content_encryption_algorithms,
                            'compression_methods' => $compression_methods,
                            'header_checkers' => $header_checkers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    /**
     * @param string[] $claimCheckers
     */
    public static function addClaimChecker(
        ContainerBuilder $container,
        string $name,
        array $claimCheckers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'claims' => [
                        $name => [
                            'is_public' => $is_public,
                            'claims' => $claimCheckers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'checkers');
    }

    /**
     * @param string[] $headerCheckers
     */
    public static function addHeaderChecker(
        ContainerBuilder $container,
        string $name,
        array $headerCheckers,
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'headers' => [
                        $name => [
                            'is_public' => $is_public,
                            'headers' => $headerCheckers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'checkers');
    }

    public static function addKey(
        ContainerBuilder $container,
        string $name,
        string $type,
        array $parameters,
        bool $is_public = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $is_public;
        $parameters['tags'] = $tags;
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

    public static function addKeyset(
        ContainerBuilder $container,
        string $name,
        string $type,
        array $parameters,
        bool $is_public = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $is_public;
        $parameters['tags'] = $tags;
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

    public static function addKeyUri(
        ContainerBuilder $container,
        string $name,
        array $parameters,
        bool $is_public = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $is_public;
        $parameters['tags'] = $tags;
        $config = [
            self::BUNDLE_ALIAS => [
                'jwk_uris' => [
                    $name => $parameters,
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwk_uris');
    }

    public static function addJWEBuilder(
        ContainerBuilder $container,
        string $name,
        array $keyEncryptionAlgorithm,
        array $contentEncryptionAlgorithms,
        array $compressionMethods = ['DEF'],
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'builders' => [
                        $name => [
                            'is_public' => $is_public,
                            'key_encryption_algorithms' => $keyEncryptionAlgorithm,
                            'content_encryption_algorithms' => $contentEncryptionAlgorithms,
                            'compression_methods' => $compressionMethods,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    public static function addJWEDecrypter(
        ContainerBuilder $container,
        string $name,
        array $keyEncryptionAlgorithm,
        array $contentEncryptionAlgorithms,
        array $compressionMethods = ['DEF'],
        bool $is_public = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'decrypters' => [
                        $name => [
                            'is_public' => $is_public,
                            'key_encryption_algorithms' => $keyEncryptionAlgorithm,
                            'content_encryption_algorithms' => $contentEncryptionAlgorithms,
                            'compression_methods' => $compressionMethods,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'jwe');
    }

    private static function updateJoseConfiguration(ContainerBuilder $container, array $config, string $element): void
    {
        $jose_config = current($container->getExtensionConfig(self::BUNDLE_ALIAS));
        if (! is_array($jose_config)) {
            $jose_config = [];
        }
        if (! isset($jose_config[$element])) {
            $jose_config[$element] = [];
        }
        $jose_config[$element] = array_merge($jose_config[$element], $config[self::BUNDLE_ALIAS][$element]);
        $container->prependExtensionConfig(self::BUNDLE_ALIAS, $jose_config);
    }
}

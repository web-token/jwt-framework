<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Helper;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use function is_array;

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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'builders' => [
                        $name => [
                            'is_public' => $isPublic,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'verifiers' => [
                        $name => [
                            'is_public' => $isPublic,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'serializers' => [
                        $name => [
                            'is_public' => $isPublic,
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
     * @param string[] $signatureAlgorithms
     * @param string[] $header_checkers
     */
    public static function addJWSLoader(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        array $signatureAlgorithms,
        array $header_checkers,
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jws' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $isPublic,
                            'serializers' => $serializers,
                            'signature_algorithms' => $signatureAlgorithms,
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
     * @param string[] $jweSerializers
     * @param string[] $encryptionAlgorithms
     * @param null|string[] $contentEncryptionAlgorithms
     * @param null|string[] $compressionMethods
     * @param string[] $jweHeaderCheckers
     * @param string[] $jwsSerializers
     * @param string[] $signatureAlgorithms
     * @param string[] $jwsHeaderCheckers
     */
    public static function addNestedTokenLoader(
        ContainerBuilder $container,
        string $name,
        array $jweSerializers,
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers,
        bool $isPublic = true,
        array $tags = []
    ): void {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $config = [
            self::BUNDLE_ALIAS => [
                'nested_token' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $isPublic,
                            'jwe_serializers' => $jweSerializers,
                            'key_encryption_algorithms' => $encryptionAlgorithms,
                            'content_encryption_algorithms' => null,
                            'compression_methods' => $compressionMethods,
                            'jwe_header_checkers' => $jweHeaderCheckers,
                            'jws_serializers' => $jwsSerializers,
                            'signature_algorithms' => $signatureAlgorithms,
                            'jws_header_checkers' => $jwsHeaderCheckers,
                            'tags' => $tags,
                        ],
                    ],
                ],
            ],
        ];

        self::updateJoseConfiguration($container, $config, 'nested_token');
    }

    /**
     * @param string[] $jweSerializers
     * @param string[] $encryptionAlgorithms
     * @param null|string[] $contentEncryptionAlgorithms
     * @param null|string[] $compressionMethods
     * @param string[] $jwsSerializers
     * @param string[] $signatureAlgorithms
     */
    public static function addNestedTokenBuilder(
        ContainerBuilder $container,
        string $name,
        array $jweSerializers,
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods,
        array $jwsSerializers,
        array $signatureAlgorithms,
        bool $isPublic = true,
        array $tags = []
    ): void {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $config = [
            self::BUNDLE_ALIAS => [
                'nested_token' => [
                    'builders' => [
                        $name => [
                            'is_public' => $isPublic,
                            'jwe_serializers' => $jweSerializers,
                            'key_encryption_algorithms' => $encryptionAlgorithms,
                            'content_encryption_algorithms' => null,
                            'compression_methods' => $compressionMethods,
                            'jws_serializers' => $jwsSerializers,
                            'signature_algorithms' => $signatureAlgorithms,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'serializers' => [
                        $name => [
                            'is_public' => $isPublic,
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
     * @param string[] $encryptionAlgorithms
     * @param null|string[] $contentEncryptionAlgorithms
     * @param null|string[] $compressionMethods
     * @param string[] $header_checkers
     */
    public static function addJWELoader(
        ContainerBuilder $container,
        string $name,
        array $serializers,
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods,
        array $header_checkers,
        bool $isPublic = true,
        array $tags = []
    ): void {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'loaders' => [
                        $name => [
                            'is_public' => $isPublic,
                            'serializers' => $serializers,
                            'key_encryption_algorithms' => $encryptionAlgorithms,
                            'content_encryption_algorithms' => null,
                            'compression_methods' => $compressionMethods,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'claims' => [
                        $name => [
                            'is_public' => $isPublic,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $config = [
            self::BUNDLE_ALIAS => [
                'checkers' => [
                    'headers' => [
                        $name => [
                            'is_public' => $isPublic,
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $isPublic;
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $isPublic;
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
        bool $isPublic = true,
        array $tags = []
    ): void {
        $parameters['is_public'] = $isPublic;
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
        array $encryptionAlgorithm,
        null|array $contentEncryptionAlgorithms = null,
        null|array $compressionMethods = null,
        bool $isPublic = true,
        array $tags = []
    ): void {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithm = array_merge($encryptionAlgorithm, $contentEncryptionAlgorithms);
        }

        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'builders' => [
                        $name => [
                            'is_public' => $isPublic,
                            'key_encryption_algorithms' => $encryptionAlgorithm,
                            'content_encryption_algorithms' => null,
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
        array $encryptionAlgorithm,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods = null,
        bool $isPublic = true,
        array $tags = []
    ): void {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithm = array_merge($encryptionAlgorithm, $contentEncryptionAlgorithms);
        }

        $config = [
            self::BUNDLE_ALIAS => [
                'jwe' => [
                    'decrypters' => [
                        $name => [
                            'is_public' => $isPublic,
                            'key_encryption_algorithms' => $encryptionAlgorithm,
                            'content_encryption_algorithms' => null,
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

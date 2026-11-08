<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Bundle\JoseFramework\DependencyInjection\JoseFrameworkExtension;
use Jose\Bundle\JoseFramework\Helper\ConfigurationHelper;
use Jose\Bundle\JoseFramework\JoseFrameworkBundle;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * One service of the bundle configured in two places, such as a "when@prod" block or a second configuration file.
 *
 * @internal
 */
final class ConfigurationMergeTest extends TestCase
{
    private const JWS_LOADER = [
        'signature_algorithms' => ['RS256', 'HS256'],
        'serializers' => ['jws_compact', 'jws_json_general'],
        'header_checkers' => ['exp', 'iat', 'nbf'],
    ];

    private const JWE_LOADER = [
        'encryption_algorithms' => ['RSA-OAEP-256', 'A256GCM', 'RSA1_5'],
        'serializers' => ['jwe_compact', 'jwe_json_general'],
        'header_checkers' => ['exp', 'iat', 'nbf'],
    ];

    private const NESTED_TOKEN_LOADER = [
        'signature_algorithms' => ['RS256', 'HS256'],
        'encryption_algorithms' => ['RSA-OAEP-256', 'A256GCM', 'RSA1_5'],
        'jws_serializers' => ['jws_compact', 'jws_json_general'],
        'jwe_serializers' => ['jwe_compact', 'jwe_json_general'],
        'jws_header_checkers' => ['exp', 'iat', 'nbf'],
        'jwe_header_checkers' => ['exp', 'iat', 'nbf'],
    ];

    private const NESTED_TOKEN_BUILDER = [
        'signature_algorithms' => ['RS256', 'HS256'],
        'encryption_algorithms' => ['RSA-OAEP-256', 'A256GCM', 'RSA1_5'],
        'jws_serializers' => ['jws_compact', 'jws_json_general'],
        'jwe_serializers' => ['jwe_compact', 'jwe_json_general'],
    ];

    /**
     * @param list<string> $service
     * @param array<string, list<string>> $definition
     */
    #[Test]
    #[DataProvider('checkerLists')]
    public function aSecondCheckerListAddsItsCheckersToTheFirstOne(
        array $service,
        array $definition,
        string $list
    ): void {
        $config = self::process(
            self::nest($service, $definition),
            self::nest($service, [
                $list => ['custom_checker'],
            ])
        );

        static::assertSame([...$definition[$list], 'custom_checker'], self::read($config, [...$service, $list]));
    }

    /**
     * @param list<string> $service
     * @param array<string, list<string>> $definition
     */
    #[Test]
    #[DataProvider('checkerLists')]
    public function aCheckerListedInBothConfigurationsIsKeptOnce(
        array $service,
        array $definition,
        string $list
    ): void {
        $config = self::process(
            self::nest($service, $definition),
            self::nest($service, [
                $list => [$definition[$list][1], 'custom_checker'],
            ])
        );

        static::assertSame([...$definition[$list], 'custom_checker'], self::read($config, [...$service, $list]));
    }

    /**
     * @return iterable<string, array{list<string>, array<string, list<string>>, string}>
     */
    public static function checkerLists(): iterable
    {
        yield 'checkers.claims.*.claims' => [
            ['checkers', 'claims', 'api'],
            [
                'claims' => ['exp', 'iat', 'nbf'],
            ],
            'claims',
        ];
        yield 'checkers.headers.*.headers' => [
            ['checkers', 'headers', 'api'],
            [
                'headers' => ['exp', 'iat', 'nbf'],
            ],
            'headers',
        ];
        yield 'jws.loaders.*.header_checkers' => [['jws', 'loaders', 'api'], self::JWS_LOADER, 'header_checkers'];
        yield 'jwe.loaders.*.header_checkers' => [['jwe', 'loaders', 'api'], self::JWE_LOADER, 'header_checkers'];
        yield 'nested_token.loaders.*.jws_header_checkers' => [
            ['nested_token', 'loaders', 'api'],
            self::NESTED_TOKEN_LOADER,
            'jws_header_checkers',
        ];
        yield 'nested_token.loaders.*.jwe_header_checkers' => [
            ['nested_token', 'loaders', 'api'],
            self::NESTED_TOKEN_LOADER,
            'jwe_header_checkers',
        ];
    }

    /**
     * @param list<string> $service
     * @param array<string, list<string>> $definition
     */
    #[Test]
    #[DataProvider('algorithmAndSerializerLists')]
    public function aSecondAlgorithmOrSerializerListReplacesTheFirstOne(
        array $service,
        array $definition,
        string $list
    ): void {
        $config = self::process(
            self::nest($service, $definition),
            self::nest($service, [
                $list => [$definition[$list][0]],
            ])
        );

        static::assertSame([$definition[$list][0]], self::read($config, [...$service, $list]));
    }

    /**
     * @return iterable<string, array{list<string>, array<string, list<string>>, string}>
     */
    public static function algorithmAndSerializerLists(): iterable
    {
        yield 'jws.builders.*.signature_algorithms' => [
            ['jws', 'builders', 'api'],
            [
                'signature_algorithms' => ['RS256', 'HS256'],
            ],
            'signature_algorithms',
        ];
        yield 'jws.verifiers.*.signature_algorithms' => [
            ['jws', 'verifiers', 'api'],
            [
                'signature_algorithms' => ['RS256', 'HS256'],
            ],
            'signature_algorithms',
        ];
        yield 'jws.loaders.*.signature_algorithms' => [
            ['jws', 'loaders', 'api'],
            self::JWS_LOADER,
            'signature_algorithms',
        ];
        yield 'jws.loaders.*.serializers' => [['jws', 'loaders', 'api'], self::JWS_LOADER, 'serializers'];
        yield 'jwe.builders.*.encryption_algorithms' => [
            ['jwe', 'builders', 'api'],
            [
                'encryption_algorithms' => ['RSA-OAEP-256', 'A256GCM', 'RSA1_5'],
            ],
            'encryption_algorithms',
        ];
        yield 'jwe.decrypters.*.encryption_algorithms' => [
            ['jwe', 'decrypters', 'api'],
            [
                'encryption_algorithms' => ['RSA-OAEP-256', 'A256GCM', 'RSA1_5'],
            ],
            'encryption_algorithms',
        ];
        yield 'jwe.loaders.*.encryption_algorithms' => [
            ['jwe', 'loaders', 'api'],
            self::JWE_LOADER,
            'encryption_algorithms',
        ];
        yield 'jwe.loaders.*.serializers' => [['jwe', 'loaders', 'api'], self::JWE_LOADER, 'serializers'];
        foreach (array_keys(self::NESTED_TOKEN_LOADER) as $list) {
            if (! str_ends_with($list, '_header_checkers')) {
                yield 'nested_token.loaders.*.' . $list => [
                    ['nested_token', 'loaders', 'api'],
                    self::NESTED_TOKEN_LOADER,
                    $list,
                ];
            }
        }
        foreach (array_keys(self::NESTED_TOKEN_BUILDER) as $list) {
            yield 'nested_token.builders.*.' . $list => [
                ['nested_token', 'builders', 'api'],
                self::NESTED_TOKEN_BUILDER,
                $list,
            ];
        }
    }

    #[Test]
    public function aClaimCheckerAddedByAnotherBundleIsKeptWhenTheApplicationConfiguresTheSameManager(): void
    {
        $container = self::containerWith([
            'checkers' => [
                'claims' => [
                    'api' => [
                        'claims' => ['exp', 'iat', 'nbf'],
                    ],
                ],
            ],
        ]);
        ConfigurationHelper::addClaimChecker($container, 'api', ['custom_checker']);

        $config = self::processContainer($container);

        static::assertSame(['custom_checker', 'exp', 'iat', 'nbf'], $config['checkers']['claims']['api']['claims']);
    }

    #[Test]
    public function aHeaderCheckerAddedByAnotherBundleIsKeptWhenTheApplicationConfiguresTheSameManager(): void
    {
        $container = self::containerWith([
            'checkers' => [
                'headers' => [
                    'api' => [
                        'headers' => ['exp', 'iat', 'nbf'],
                    ],
                ],
            ],
        ]);
        ConfigurationHelper::addHeaderChecker($container, 'api', ['custom_checker']);

        $config = self::processContainer($container);

        static::assertSame(['custom_checker', 'exp', 'iat', 'nbf'], $config['checkers']['headers']['api']['headers']);
    }

    #[Test]
    public function theCopyOfTheApplicationConfigurationMadeByTheHelperDoesNotDuplicateItsCheckers(): void
    {
        $container = self::containerWith([
            'checkers' => [
                'claims' => [
                    'api' => [
                        'claims' => ['exp', 'iat', 'nbf'],
                    ],
                ],
            ],
            'jws' => [
                'loaders' => [
                    'api' => self::JWS_LOADER,
                ],
            ],
        ]);
        ConfigurationHelper::addHeaderChecker($container, 'other', ['custom_checker']);
        ConfigurationHelper::addJWSVerifier($container, 'other', ['ES256']);

        $config = self::processContainer($container);

        static::assertSame(['exp', 'iat', 'nbf'], $config['checkers']['claims']['api']['claims']);
        static::assertSame(['exp', 'iat', 'nbf'], $config['jws']['loaders']['api']['header_checkers']);
        static::assertSame(['RS256', 'HS256'], $config['jws']['loaders']['api']['signature_algorithms']);
    }

    #[Test]
    public function anExpiredTokenIsRejectedWhenTheSecondConfigurationAddsAClaimChecker(): void
    {
        $container = self::containerWith(
            [
                'checkers' => [
                    'claims' => [
                        'api' => [
                            'claims' => ['exp', 'iat', 'nbf'],
                        ],
                    ],
                ],
            ],
            [
                'checkers' => [
                    'claims' => [
                        'api' => [
                            'claims' => ['aud_api'],
                        ],
                    ],
                ],
            ]
        );
        $container->register(ClockInterface::class, MockClock::class);
        $container->register('event_dispatcher', EventDispatcher::class);
        $container->register('aud_api', AudienceChecker::class)
            ->setArguments(['api'])
            ->addTag('jose.checker.claim', [
                'alias' => 'aud_api',
            ]);
        $container->compile(true);
        $manager = $container->get('jose.claim_checker.api');
        static::assertInstanceOf(ClaimCheckerManager::class, $manager);

        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('The token expired.');

        $manager->check([
            'exp' => time() - 3600,
            'iat' => time() - 7200,
            'nbf' => time() - 7200,
            'aud' => 'api',
        ]);
    }

    /**
     * @param array<string, mixed> ...$configs
     */
    private static function containerWith(array ...$configs): ContainerBuilder
    {
        $bundle = new JoseFrameworkBundle();
        $container = new ContainerBuilder();
        $container->setParameter('kernel.debug', false);
        $container->registerExtension($bundle->getContainerExtension());
        foreach ($configs as $config) {
            $container->loadFromExtension('jose', $config);
        }
        $bundle->build($container);

        return $container;
    }

    /**
     * @return array<string, mixed>
     */
    private static function processContainer(ContainerBuilder $container): array
    {
        $extension = $container->getExtension('jose');
        static::assertInstanceOf(JoseFrameworkExtension::class, $extension);
        $configs = $container->getExtensionConfig('jose');

        return (new Processor())->processConfiguration($extension->getConfiguration($configs, $container), $configs);
    }

    /**
     * @param array<string, mixed> ...$configs
     *
     * @return array<string, mixed>
     */
    private static function process(array ...$configs): array
    {
        return self::processContainer(self::containerWith(...$configs));
    }

    /**
     * @param list<string> $path
     * @param array<string, mixed> $value
     *
     * @return array<string, mixed>
     */
    private static function nest(array $path, array $value): array
    {
        foreach (array_reverse($path) as $key) {
            $value = [
                $key => $value,
            ];
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string> $path
     */
    private static function read(array $config, array $path): mixed
    {
        foreach ($path as $key) {
            static::assertIsArray($config);
            static::assertArrayHasKey($key, $config);
            $config = $config[$key];
        }

        return $config;
    }
}

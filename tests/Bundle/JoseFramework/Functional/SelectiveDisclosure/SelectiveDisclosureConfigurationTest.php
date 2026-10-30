<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\SelectiveDisclosure;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Checker\CheckerSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\SelectiveDisclosure\SelectiveDisclosure;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature\SignatureSource;
use Jose\Tests\Bundle\JoseFramework\ConfigurationAssertionsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class SelectiveDisclosureConfigurationTest extends TestCase
{
    use ConfigurationAssertionsTrait;

    #[Test]
    #[DataProvider('validConfigurations')]
    public function theConfigurationIsValid(mixed $configuration): void
    {
        $this->assertConfigurationIsValid([[
            'selective_disclosure' => $configuration,
        ]]);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function validConfigurations(): iterable
    {
        yield 'false' => [false];
        yield 'null' => [null];
        yield 'empty' => [[]];
        yield 'no service' => [[
            'issuers' => [],
            'holders' => [],
            'verifiers' => [],
        ]];
        yield 'one service per role' => [[
            'issuers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'hash_algorithm' => 'sha-512',
                    'minimum_decoy_digests' => 2,
                    'maximum_decoy_digests' => 5,
                ],
            ],
            'holders' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                ],
            ],
            'verifiers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'key_binding_signature_algorithms' => ['ES256', 'EdDSA'],
                    'claim_checkers' => ['exp'],
                    'mandatory_claims' => ['iss', 'exp'],
                    'hash_algorithms' => ['sha-256', 'sha-512'],
                    'key_binding_max_age' => 60,
                    'allowed_time_drift' => 5,
                ],
            ],
        ]];
    }

    #[Test]
    public function theDefaultValuesAreThoseOfTheLibrary(): void
    {
        $this->assertProcessedConfigurationEquals([[
            'selective_disclosure' => [
                'issuers' => [
                    'foo' => [
                        'signature_algorithms' => ['ES256'],
                    ],
                ],
                'verifiers' => [
                    'foo' => [
                        'signature_algorithms' => ['ES256'],
                    ],
                ],
            ],
        ]], [
            'selective_disclosure' => [
                'issuers' => [
                    'foo' => [
                        'signature_algorithms' => ['ES256'],
                        'is_public' => true,
                        'hash_algorithm' => 'sha-256',
                        'minimum_decoy_digests' => 0,
                        'maximum_decoy_digests' => null,
                        'tags' => [],
                    ],
                ],
                'holders' => [],
                'verifiers' => [
                    'foo' => [
                        'signature_algorithms' => ['ES256'],
                        'is_public' => true,
                        'header_checkers' => [],
                        'key_binding_signature_algorithms' => [],
                        'key_binding_header_checkers' => [],
                        'claim_checkers' => [],
                        'mandatory_claims' => [],
                        'hash_algorithms' => [],
                        'key_binding_max_age' => 300,
                        'allowed_time_drift' => 0,
                        'tags' => [],
                    ],
                ],
            ],
        ], 'selective_disclosure');
    }

    #[Test]
    #[DataProvider('invalidConfigurations')]
    public function theConfigurationIsInvalid(array $configuration, string $message): void
    {
        $this->assertConfigurationIsInvalid([[
            'selective_disclosure' => $configuration,
        ]], $message);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidConfigurations(): iterable
    {
        foreach (['issuers', 'holders', 'verifiers'] as $role) {
            yield $role . ' without signature algorithm' => [[
                $role => [
                    'foo' => [],
                ],
            ], 'The child config "signature_algorithms" under "jose.selective_disclosure.' . $role . '.foo" must be configured'];
        }
        yield 'unsupported hash algorithm of an Issuer' => [[
            'issuers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'hash_algorithm' => 'sha256',
                ],
            ],
        ], 'The value "sha256" is not allowed for path "jose.selective_disclosure.issuers.foo.hash_algorithm".'];
        yield 'negative number of decoy digests' => [[
            'issuers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'minimum_decoy_digests' => -1,
                ],
            ],
        ], 'The value -1 is too small for path "jose.selective_disclosure.issuers.foo.minimum_decoy_digests".'];
        yield 'unsupported hash algorithm of a Verifier' => [[
            'verifiers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'hash_algorithms' => ['md5'],
                ],
            ],
        ], 'The value "md5" is not allowed for path "jose.selective_disclosure.verifiers.foo.hash_algorithms.0".'];
        yield 'negative maximum age' => [[
            'verifiers' => [
                'foo' => [
                    'signature_algorithms' => ['ES256'],
                    'key_binding_max_age' => -1,
                ],
            ],
        ], 'The value -1 is too small for path "jose.selective_disclosure.verifiers.foo.key_binding_max_age".'];
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [
            new CoreSource(),
            new CheckerSource(),
            new SignatureSource(),
            new SelectiveDisclosure(),
        ]);
    }
}

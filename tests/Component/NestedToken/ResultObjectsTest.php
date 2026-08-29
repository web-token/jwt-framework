<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\NestedToken\NestedTokenBuilderFactory;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\NestedToken\NestedTokenLoaderFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use PHPUnit\Framework\Attributes\Test;
use const E_USER_DEPRECATED;

/**
 * The "$signature" output parameter of the nested token loader is deprecated and replaced with a result object. The
 * "load()" method is implemented on top of the new one and keeps its exact behaviour.
 *
 * @internal
 */
final class ResultObjectsTest extends NestedTokenTestCase
{
    private ?JWK $encryptionKey = null;

    private ?JWK $signatureKey = null;

    #[Test]
    public function theLoaderReturnsTheIndexOfTheVerifiedSignature(): void
    {
        $result = $this->getNestedTokenLoader()
            ->loadAndVerify(
                $this->createToken(),
                new JWKSet([$this->getEncryptionKey()]),
                new JWKSet([$this->getSignatureKey()])
            );

        static::assertSame('Live long and prosper.', $result->getJws()->getPayload());
        static::assertSame(0, $result->getSignatureIndex());
        static::assertSame($this->getSignatureKey()->all(), $result->getKey()->all());
    }

    #[Test]
    public function onlyThePassedSignatureArgumentIsDeprecated(): void
    {
        $token = $this->createToken();
        $encryptionKeySet = new JWKSet([$this->getEncryptionKey()]);
        $signatureKeySet = new JWKSet([$this->getSignatureKey()]);
        $signature = null;
        $deprecations = $this->collectDeprecations(function () use (
            $token,
            $encryptionKeySet,
            $signatureKeySet,
            &$signature
        ): void {
            $this->getNestedTokenLoader()
                ->load($token, $encryptionKeySet, $signatureKeySet);
            $this->getNestedTokenLoader()
                ->load($token, $encryptionKeySet, $signatureKeySet, $signature);
        });

        static::assertSame(0, $signature);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString('Passing the "$signature" argument', $deprecations[0]);
    }

    private function getNestedTokenLoader(): NestedTokenLoader
    {
        $loaderFactory = new NestedTokenLoaderFactory(
            $this->getJWELoaderFactory(),
            new JWSLoaderFactory(
                $this->getJWSSerializerManagerFactory(),
                new JWSVerifierFactory($this->getSignatureAlgorithmManagerFactory()),
                null
            )
        );

        return $loaderFactory->create(['jwe_compact'], ['A256KW', 'A256GCM'], [], ['jws_compact'], ['HS256'], []);
    }

    private function getSignatureAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        return new AlgorithmManagerFactory([new HS256()]);
    }

    private function getJWSSerializerManagerFactory(): JWSSerializerManagerFactory
    {
        $factory = new JWSSerializerManagerFactory();
        $factory->add(new CompactSerializer());

        return $factory;
    }

    private function getEncryptionKey(): JWK
    {
        if ($this->encryptionKey === null) {
            $this->encryptionKey = JWKFactory::createOctKey(256, [
                'alg' => 'A256KW',
                'use' => 'enc',
            ]);
        }

        return $this->encryptionKey;
    }

    private function getSignatureKey(): JWK
    {
        if ($this->signatureKey === null) {
            $this->signatureKey = JWKFactory::createOctKey(512, [
                'alg' => 'HS256',
                'use' => 'sig',
            ]);
        }

        return $this->signatureKey;
    }

    private function createToken(): string
    {
        $builderFactory = new NestedTokenBuilderFactory(
            $this->getJWEBuilderFactory(),
            $this->getJWESerializerManagerFactory(),
            new JWSBuilderFactory($this->getSignatureAlgorithmManagerFactory()),
            $this->getJWSSerializerManagerFactory()
        );
        $builder = $builderFactory->create(['jwe_compact'], ['A256KW', 'A256GCM'], ['jws_compact'], ['HS256']);

        return $builder->create(
            'Live long and prosper.',
            [
                [
                    'key' => $this->getSignatureKey(),
                    'protected_header' => [
                        'alg' => 'HS256',
                    ],
                ],
            ],
            'jws_compact',
            [
                'alg' => 'A256KW',
                'enc' => 'A256GCM',
            ],
            [],
            [
                [
                    'key' => $this->getEncryptionKey(),
                ],
            ],
            'jwe_compact'
        );
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}

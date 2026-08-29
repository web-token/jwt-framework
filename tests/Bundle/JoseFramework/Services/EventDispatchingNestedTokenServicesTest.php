<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenIssuedEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Bundle\JoseFramework\Services\EventDispatchingNestedTokenBuilder;
use Jose\Bundle\JoseFramework\Services\EventDispatchingNestedTokenLoader;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * The event dispatching nested token services of the bundle used to extend the ones of the library. They are replaced
 * by decorators, which dispatch the same events without inheriting anything.
 *
 * @internal
 */
final class EventDispatchingNestedTokenServicesTest extends TestCase
{
    #[Test]
    public function theBuilderDispatchesTheIssuedEventAndTheLoaderReadsTheTokenBack(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $builder = new EventDispatchingNestedTokenBuilder($this->builder(), $dispatcher);
        $loader = new EventDispatchingNestedTokenLoader($this->loader(), $dispatcher);

        $token = $builder->create(
            'Hello World!',
            [[
                'key' => $this->signatureKey(),
                'protected_header' => [
                    'alg' => 'HS256',
                ],
            ]],
            'jws_compact',
            [
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
            ],
            [],
            [[
                'key' => $this->encryptionKey(),
            ]],
            'jwe_compact'
        );

        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(NestedTokenIssuedEvent::class, $event);
        static::assertSame($token, $event->getNestedToken());

        $signature = null;
        $jws = $loader->load(
            $token,
            new JWKSet([$this->encryptionKey()]),
            new JWKSet([$this->signatureKey()]),
            $signature
        );

        static::assertSame('Hello World!', $jws->getPayload());
        static::assertInstanceOf(NestedTokenLoadingSuccessEvent::class, $dispatcher->lastEvent());
    }

    #[Test]
    public function theLoaderDispatchesTheFailureEvent(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $loader = new EventDispatchingNestedTokenLoader($this->loader(), $dispatcher);
        $signature = null;

        try {
            $loader->load(
                'not.a.nested.token',
                new JWKSet([$this->encryptionKey()]),
                new JWKSet([$this->signatureKey()]),
                $signature
            );
            static::fail('The token cannot be loaded: the load was expected to fail.');
        } catch (Throwable) {
        }

        static::assertInstanceOf(NestedTokenLoadingFailureEvent::class, $dispatcher->lastEvent());
    }

    private function builder(): NestedTokenBuilder
    {
        return new NestedTokenBuilder(
            new JWEBuilder($this->encryptionAlgorithms()),
            new JWESerializerManager([new JWECompactSerializer()]),
            new JWSBuilder($this->signatureAlgorithms()),
            new JWSSerializerManager([new JWSCompactSerializer()])
        );
    }

    private function loader(): NestedTokenLoader
    {
        return new NestedTokenLoader(
            new JWELoader(new JWESerializerManager([new JWECompactSerializer()]), new JWEDecrypter(
                $this->encryptionAlgorithms()
            ), null),
            new JWSLoader(new JWSSerializerManager([new JWSCompactSerializer()]), new JWSVerifier(
                $this->signatureAlgorithms()
            ), null)
        );
    }

    private function signatureAlgorithms(): AlgorithmManager
    {
        return new AlgorithmManager([new HS256()]);
    }

    private function encryptionAlgorithms(): AlgorithmManager
    {
        return new AlgorithmManager([new A256KW(), new A256CBCHS512()]);
    }

    private function signatureKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AMNwmSpJ2WdOFyOgKvjRj',
        ]);
    }

    private function encryptionKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
    }
}

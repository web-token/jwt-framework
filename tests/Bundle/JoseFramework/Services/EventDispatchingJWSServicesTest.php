<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSBuiltSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWSLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSLoadingSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWSBuilder;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWSLoader;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWSVerifier;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * The event dispatching services of the bundle used to extend the services of the library. They are replaced by
 * decorators, which dispatch the same events without inheriting anything.
 *
 * @internal
 */
final class EventDispatchingJWSServicesTest extends TestCase
{
    #[Test]
    public function theBuilderDispatchesTheSuccessEventAndReturnsTheToken(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $builder = new EventDispatchingJWSBuilder($this->builder(), $dispatcher);

        $jws = $builder
            ->withPayload('Hello World!')
            ->addSignature($this->key(), [
                'alg' => 'HS256',
            ])
            ->build();

        static::assertSame('Hello World!', $jws->getPayload());
        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(JWSBuiltSuccessEvent::class, $event);
        static::assertSame($jws, $event->getJws());
    }

    #[Test]
    public function theBuilderDispatchesTheFailureEventWithTheDataItWasGiven(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $key = $this->key();
        $protectedHeader = [
            'alg' => 'HS256',
            'b64' => false,
            'crit' => ['b64'],
        ];
        $builder = (new EventDispatchingJWSBuilder($this->builder(), $dispatcher))
            ->withPayload("\xB1\x31")
            ->addSignature($key, $protectedHeader);

        try {
            $builder->build();
            static::fail('The payload is not encoded in UTF-8: the build was expected to fail.');
        } catch (Throwable) {
        }

        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(JWSBuiltFailureEvent::class, $event);
        static::assertSame("\xB1\x31", $event->getPayload());
        static::assertFalse($event->isPayloadDetached());
        static::assertFalse($event->getisPayloadEncoded());
        static::assertSame([[
            'signature_key' => $key,
            'protected_header' => $protectedHeader,
            'header' => [],
        ]], $event->getSignatures());
    }

    #[Test]
    public function theVerifierDispatchesTheSuccessAndTheFailureEvents(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $verifier = new EventDispatchingJWSVerifier(new JWSVerifier($this->algorithms()), $dispatcher);
        $jws = $this->token();

        static::assertTrue($verifier->verifyWithKey($jws, $this->key(), 0));
        static::assertInstanceOf(JWSVerificationSuccessEvent::class, $dispatcher->lastEvent());

        static::assertFalse($verifier->verifyWithKey($jws, $this->otherKey(), 0));
        static::assertInstanceOf(JWSVerificationFailureEvent::class, $dispatcher->lastEvent());
    }

    #[Test]
    public function theVerifierForwardsTheCallableUsedToObserveTheDiscardedKeys(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $verifier = new EventDispatchingJWSVerifier(new JWSVerifier($this->algorithms()), $dispatcher);
        $jws = $this->token();
        $jwk = null;
        $errors = [];

        $verifier->verifyWithKeySet(
            $jws,
            new JWKSet([$this->unusableKey()]),
            0,
            null,
            $jwk,
            static function (Throwable $throwable) use (&$errors): void {
                $errors[] = $throwable;
            }
        );

        static::assertCount(1, $errors);
    }

    #[Test]
    public function theLoaderDispatchesTheSuccessAndTheFailureEvents(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $loader = new EventDispatchingJWSLoader(
            new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new JWSVerifier(
                $this->algorithms()
            ), null),
            $dispatcher
        );
        $token = (new CompactSerializer())->serialize($this->token(), 0);
        $signature = null;

        $jws = $loader->loadAndVerifyWithKeySet($token, new JWKSet([$this->key()]), $signature);
        static::assertSame('Hello World!', $jws->getPayload());
        static::assertInstanceOf(JWSLoadingSuccessEvent::class, $dispatcher->lastEvent());

        try {
            $loader->loadAndVerifyWithKeySet($token, new JWKSet([$this->otherKey()]), $signature);
            static::fail('The key set cannot verify the token: the load was expected to fail.');
        } catch (Throwable) {
        }
        static::assertInstanceOf(JWSLoadingFailureEvent::class, $dispatcher->lastEvent());
    }

    #[Test]
    public function theLoaderKeepsTheReasonOfTheFailureWhenTheVerifierIsDecorated(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $loader = new EventDispatchingJWSLoader(
            new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new EventDispatchingJWSVerifier(
                new JWSVerifier($this->algorithms()),
                $dispatcher
            ), null),
            $dispatcher
        );
        $token = (new CompactSerializer())->serialize($this->token(), 0);
        $signature = null;

        try {
            $loader->loadAndVerifyWithKeySet($token, new JWKSet([$this->unusableKey()]), $signature);
            static::fail('The key cannot be used: the load was expected to fail.');
        } catch (Throwable $throwable) {
            static::assertNotNull($throwable->getPrevious());
        }
    }

    private function algorithms(): AlgorithmManager
    {
        return new AlgorithmManager([new HS256()]);
    }

    private function builder(): JWSBuilder
    {
        return new JWSBuilder($this->algorithms());
    }

    private function key(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AMNwmSpJ2WdOFyOgKvjRj',
        ]);
    }

    private function otherKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
    }

    private function unusableKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
            'use' => 'enc',
        ]);
    }

    private function token(): JWS
    {
        return $this->builder()
            ->withPayload('Hello World!')
            ->addSignature($this->key(), [
                'alg' => 'HS256',
            ])
            ->build();
    }
}

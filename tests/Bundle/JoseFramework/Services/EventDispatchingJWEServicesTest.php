<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEBuiltSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWEBuilder;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWEDecrypter;
use Jose\Bundle\JoseFramework\Services\EventDispatchingJWELoader;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * The event dispatching services of the bundle used to extend the services of the library. They are replaced by
 * decorators, which dispatch the same events without inheriting anything.
 *
 * @internal
 */
final class EventDispatchingJWEServicesTest extends TestCase
{
    private const SHARED_PROTECTED_HEADER = [
        'alg' => 'A256KW',
        'enc' => 'A256CBC-HS512',
    ];

    #[Test]
    public function theBuilderDispatchesTheSuccessEventAndReturnsTheToken(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $builder = new EventDispatchingJWEBuilder($this->builder(), $dispatcher);

        $jwe = $builder
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader(self::SHARED_PROTECTED_HEADER)
            ->addRecipient($this->key())
            ->build();

        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(JWEBuiltSuccessEvent::class, $event);
        static::assertSame($jwe, $event->getJwe());
    }

    #[Test]
    public function theBuilderDispatchesTheFailureEventWithTheDataItWasGiven(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $key = $this->key();
        $builder = (new EventDispatchingJWEBuilder($this->builder(), $dispatcher))
            ->withAAD('additional data')
            ->withSharedProtectedHeader(self::SHARED_PROTECTED_HEADER)
            ->withSharedHeader([
                'cty' => 'JWT',
            ])
            ->addRecipient($key);

        try {
            $builder->build();
            static::fail('The payload is not set: the build was expected to fail.');
        } catch (Throwable) {
        }

        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(JWEBuiltFailureEvent::class, $event);
        static::assertNull($event->getPayload());
        static::assertSame('additional data', $event->getAad());
        static::assertSame(self::SHARED_PROTECTED_HEADER, $event->getSharedProtectedHeader());
        static::assertSame([
            'cty' => 'JWT',
        ], $event->getSharedHeader());
        static::assertSame([[
            'key' => $key,
            'header' => [],
        ]], $event->getRecipients());
    }

    #[Test]
    public function theBuilderForgetsTheAdditionalAuthenticatedDataOnceItIsUnset(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $builder = (new EventDispatchingJWEBuilder($this->builder(), $dispatcher))
            ->withAAD('additional data')
            ->withAAD(null);

        try {
            $builder->build();
            static::fail('The payload is not set: the build was expected to fail.');
        } catch (Throwable) {
        }

        $event = $dispatcher->lastEvent();
        static::assertInstanceOf(JWEBuiltFailureEvent::class, $event);
        static::assertNull($event->getAad());
    }

    #[Test]
    public function theDecrypterDispatchesTheSuccessAndTheFailureEvents(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $decrypter = new EventDispatchingJWEDecrypter(new JWEDecrypter($this->algorithms()), $dispatcher);

        $jwe = $this->token();
        static::assertTrue($decrypter->decryptUsingKey($jwe, $this->key(), 0));
        static::assertInstanceOf(JWEDecryptionSuccessEvent::class, $dispatcher->lastEvent());

        $jwe = $this->token();
        static::assertFalse($decrypter->decryptUsingKey($jwe, $this->otherKey(), 0));
        static::assertInstanceOf(JWEDecryptionFailureEvent::class, $dispatcher->lastEvent());
    }

    #[Test]
    public function theDecrypterForwardsTheCallableUsedToObserveTheDiscardedKeys(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $decrypter = new EventDispatchingJWEDecrypter(new JWEDecrypter($this->algorithms()), $dispatcher);
        $jwe = $this->token();
        $jwk = null;
        $errors = [];

        $decrypter->decryptUsingKeySet(
            $jwe,
            new JWKSet([$this->unusableKey()]),
            0,
            $jwk,
            null,
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
        $loader = new EventDispatchingJWELoader(
            new JWELoader(new JWESerializerManager([new CompactSerializer()]), new JWEDecrypter(
                $this->algorithms()
            ), null),
            $dispatcher
        );
        $token = (new CompactSerializer())->serialize($this->token(), 0);
        $recipient = null;

        $jwe = $loader->loadAndDecryptWithKeySet($token, new JWKSet([$this->key()]), $recipient);
        static::assertSame('Hello World!', $jwe->getPayload());
        static::assertInstanceOf(JWELoadingSuccessEvent::class, $dispatcher->lastEvent());

        try {
            $loader->loadAndDecryptWithKeySet($token, new JWKSet([$this->otherKey()]), $recipient);
            static::fail('The key set cannot decrypt the token: the load was expected to fail.');
        } catch (Throwable) {
        }
        static::assertInstanceOf(JWELoadingFailureEvent::class, $dispatcher->lastEvent());
    }

    private function algorithms(): AlgorithmManager
    {
        return new AlgorithmManager([new A256KW(), new A256CBCHS512()]);
    }

    private function builder(): JWEBuilder
    {
        return new JWEBuilder($this->algorithms());
    }

    private function key(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);
    }

    private function otherKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRI',
        ]);
    }

    private function unusableKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
            'use' => 'sig',
        ]);
    }

    private function token(): JWE
    {
        return $this->builder()
            ->withPayload('Hello World!')
            ->withSharedProtectedHeader(self::SHARED_PROTECTED_HEADER)
            ->addRecipient($this->key())
            ->build();
    }
}

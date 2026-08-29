<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\ClaimCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\ClaimCheckedSuccessEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Bundle\JoseFramework\Services\EventDispatchingClaimCheckerManager;
use Jose\Bundle\JoseFramework\Services\EventDispatchingHeaderCheckerManager;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * The event dispatching checker managers of the bundle used to extend the ones of the library. They are replaced by
 * decorators, which dispatch the same events without inheriting anything.
 *
 * @internal
 */
final class EventDispatchingCheckerServicesTest extends TestCase
{
    #[Test]
    public function theClaimCheckerManagerDispatchesTheSuccessEvent(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $manager = new EventDispatchingClaimCheckerManager(
            new ClaimCheckerManager([new IssuerChecker(['issuer'])]),
            $dispatcher
        );

        $checked = $manager->check([
            'iss' => 'issuer',
        ], ['iss']);

        static::assertSame([
            'iss' => 'issuer',
        ], $checked);
        static::assertInstanceOf(ClaimCheckedSuccessEvent::class, $dispatcher->lastEvent());
        static::assertCount(1, $manager->getCheckers());
    }

    #[Test]
    public function theClaimCheckerManagerDispatchesTheFailureEvent(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $manager = new EventDispatchingClaimCheckerManager(
            new ClaimCheckerManager([new IssuerChecker(['issuer'])]),
            $dispatcher
        );

        try {
            $manager->check([
                'iss' => 'another issuer',
            ], ['iss']);
            static::fail('The issuer is not allowed: the check was expected to fail.');
        } catch (Throwable) {
        }

        static::assertInstanceOf(ClaimCheckedFailureEvent::class, $dispatcher->lastEvent());
    }

    #[Test]
    public function theHeaderCheckerManagerDispatchesTheSuccessEvent(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $manager = new EventDispatchingHeaderCheckerManager(
            new HeaderCheckerManager([new IssuerChecker(['issuer'])], [new JWSTokenSupport()]),
            $dispatcher
        );

        $manager->check($this->token([
            'alg' => 'HS256',
            'iss' => 'issuer',
        ]), 0, ['iss']);

        static::assertInstanceOf(HeaderCheckedSuccessEvent::class, $dispatcher->lastEvent());
        static::assertCount(1, $manager->getCheckers());
    }

    #[Test]
    public function theHeaderCheckerManagerDispatchesTheFailureEvent(): void
    {
        $dispatcher = new CollectingEventDispatcher();
        $manager = new EventDispatchingHeaderCheckerManager(
            new HeaderCheckerManager([new IssuerChecker(['issuer'])], [new JWSTokenSupport()]),
            $dispatcher
        );

        try {
            $manager->check($this->token([
                'alg' => 'HS256',
                'iss' => 'another issuer',
            ]), 0, ['iss']);
            static::fail('The issuer is not allowed: the check was expected to fail.');
        } catch (Throwable) {
        }

        static::assertInstanceOf(HeaderCheckedFailureEvent::class, $dispatcher->lastEvent());
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function token(array $protectedHeader): JWS
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => '3pWc2vAZpHoV7XmCT-z2hWhdQquwQwW5a3XTojbf87c',
        ]);

        return (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->withPayload('Hello World!')
            ->addSignature($key, $protectedHeader)
            ->build();
    }
}

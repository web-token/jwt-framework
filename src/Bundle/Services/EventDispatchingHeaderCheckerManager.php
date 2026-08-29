<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWT;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever header parameters are checked, without extending the manager it decorates.
 */
final readonly class EventDispatchingHeaderCheckerManager implements HeaderCheckerManagerInterface
{
    public function __construct(
        private HeaderCheckerManagerInterface $manager,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getCheckers(): array
    {
        return $this->manager->getCheckers();
    }

    #[Override]
    public function check(JWT $jwt, int $index, array $mandatoryHeaderParameters = []): void
    {
        try {
            $this->manager->check($jwt, $index, $mandatoryHeaderParameters);
            $this->eventDispatcher->dispatch(
                new HeaderCheckedSuccessEvent($jwt, $index, $mandatoryHeaderParameters)
            );
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(
                new HeaderCheckedFailureEvent($jwt, $index, $mandatoryHeaderParameters, $throwable)
            );

            throw $throwable;
        }
    }
}

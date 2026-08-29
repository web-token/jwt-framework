<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\ClaimCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\ClaimCheckedSuccessEvent;
use Jose\Component\Checker\ClaimCheckerManagerInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever claims are checked, without extending the manager it decorates.
 */
final readonly class EventDispatchingClaimCheckerManager implements ClaimCheckerManagerInterface
{
    public function __construct(
        private ClaimCheckerManagerInterface $manager,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getCheckers(): array
    {
        return $this->manager->getCheckers();
    }

    #[Override]
    public function check(array $claims, array $mandatoryClaims = []): array
    {
        try {
            $checkedClaims = $this->manager->check($claims, $mandatoryClaims);
            $this->eventDispatcher->dispatch(
                new ClaimCheckedSuccessEvent($claims, $mandatoryClaims, $checkedClaims)
            );

            return $checkedClaims;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new ClaimCheckedFailureEvent($claims, $mandatoryClaims, $throwable));

            throw $throwable;
        }
    }
}

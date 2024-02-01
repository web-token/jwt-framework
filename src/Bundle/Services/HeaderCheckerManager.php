<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManager as BaseHeaderCheckerManager;
use Jose\Component\Core\JWT;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class HeaderCheckerManager extends BaseHeaderCheckerManager
{
    public function __construct(
        array $checkers,
        array $tokenTypes,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($checkers, $tokenTypes);
    }

    public function check(JWT $jwt, int $index, array $mandatoryHeaderParameters = []): void
    {
        try {
            BaseHeaderCheckerManager::check($jwt, $index, $mandatoryHeaderParameters);
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

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\ClaimCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\ClaimCheckedSuccessEvent;
use Jose\Component\Checker\ClaimCheckerManager as BaseClaimCheckerManager;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class ClaimCheckerManager extends BaseClaimCheckerManager
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct($checkers, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($checkers);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function check(array $claims, array $mandatoryClaims = []): array
    {
        try {
            $checkedClaims = BaseClaimCheckerManager::check($claims, $mandatoryClaims);
            $this->eventDispatcher->dispatch(
                new ClaimCheckedSuccessEvent($claims, $mandatoryClaims, $checkedClaims)
            );

            return $checkedClaims;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(
                new ClaimCheckedFailureEvent($claims, $mandatoryClaims, $throwable)
            );

            throw $throwable;
        }
    }
}

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

use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManager as BaseHeaderCheckerManager;
use Jose\Component\Core\JWT;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class HeaderCheckerManager extends BaseHeaderCheckerManager
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(array $checkers, array $tokenTypes, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($checkers, $tokenTypes);
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @throws Throwable if a checker failed to verify a header parameter
     */
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

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\Events;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManager as BaseHeaderCheckerManager;
use Jose\Component\Core\JWT;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

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

    public function check(JWT $jwt, int $index, array $mandatoryHeaderParameters = []): void
    {
        try {
            BaseHeaderCheckerManager::check($jwt, $index, $mandatoryHeaderParameters);
            $this->eventDispatcher->dispatch(
                Events::HEADER_CHECK_SUCCESS,
                new HeaderCheckedSuccessEvent($jwt, $index, $mandatoryHeaderParameters)
            );
        } catch (\Throwable $throwable) {
            $this->eventDispatcher->dispatch(
                Events::HEADER_CHECK_FAILURE,
                new HeaderCheckedFailureEvent($jwt, $index, $mandatoryHeaderParameters, $throwable)
            );

            throw $throwable;
        }
    }
}

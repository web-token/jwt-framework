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

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Bundle\JoseFramework\Event\ClaimCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\ClaimCheckedSuccessEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedFailureEvent;
use Jose\Bundle\JoseFramework\Event\HeaderCheckedSuccessEvent;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManager;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManager;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

class CheckerCollector implements Collector, EventSubscriberInterface
{
    /**
     * @var null|ClaimCheckerManagerFactory
     */
    private $claimCheckerManagerFactory;

    /**
     * @var null|HeaderCheckerManagerFactory
     */
    private $headerCheckerManagerFactory;

    /**
     * @var array
     */
    private $headerCheckedSuccesses = [];

    /**
     * @var array
     */
    private $headerCheckedFailures = [];

    /**
     * @var array
     */
    private $claimCheckedSuccesses = [];

    /**
     * @var array
     */
    private $claimCheckedFailures = [];

    /**
     * @var HeaderCheckerManager[]
     */
    private $headerCheckerManagers = [];

    /**
     * @var ClaimCheckerManager[]
     */
    private $claimCheckerManagers = [];

    public function __construct(?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory = null)
    {
        $this->claimCheckerManagerFactory = $claimCheckerManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectHeaderCheckerManagers($data);
        $this->collectSupportedHeaderCheckers($data);
        $this->collectClaimCheckerManagers($data);
        $this->collectSupportedClaimCheckers($data);
        $this->collectEvents($data);
    }

    public function addHeaderCheckerManager(string $id, HeaderCheckerManager $headerCheckerManager): void
    {
        $this->headerCheckerManagers[$id] = $headerCheckerManager;
    }

    public function addClaimCheckerManager(string $id, ClaimCheckerManager $claimCheckerManager): void
    {
        $this->claimCheckerManagers[$id] = $claimCheckerManager;
    }

    public static function getSubscribedEvents()
    {
        return [
            HeaderCheckedSuccessEvent::class => ['catchHeaderCheckSuccess'],
            HeaderCheckedFailureEvent::class => ['catchHeaderCheckFailure'],
            ClaimCheckedSuccessEvent::class => ['catchClaimCheckSuccess'],
            ClaimCheckedFailureEvent::class => ['catchClaimCheckFailure'],
        ];
    }

    public function catchHeaderCheckSuccess(HeaderCheckedSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->headerCheckedSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchHeaderCheckFailure(HeaderCheckedFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->headerCheckedFailures[] = $cloner->cloneVar($event);
    }

    public function catchClaimCheckSuccess(ClaimCheckedSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->claimCheckedSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchClaimCheckFailure(ClaimCheckedFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->claimCheckedFailures[] = $cloner->cloneVar($event);
    }

    private function collectHeaderCheckerManagers(array &$data): void
    {
        $data['checker']['header_checker_managers'] = [];
        foreach ($this->headerCheckerManagers as $id => $checkerManager) {
            $data['checker']['header_checker_managers'][$id] = [];
            foreach ($checkerManager->getCheckers() as $checker) {
                $data['checker']['header_checker_managers'][$id][] = [
                    'header' => $checker->supportedHeader(),
                    'protected' => $checker->protectedHeaderOnly(),
                ];
            }
        }
    }

    private function collectSupportedHeaderCheckers(array &$data): void
    {
        $data['checker']['header_checkers'] = [];
        if (null !== $this->headerCheckerManagerFactory) {
            $aliases = $this->headerCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $data['checker']['header_checkers'][$alias] = [
                    'header' => $checker->supportedHeader(),
                    'protected' => $checker->protectedHeaderOnly(),
                ];
            }
        }
    }

    private function collectClaimCheckerManagers(array &$data): void
    {
        $data['checker']['claim_checker_managers'] = [];
        foreach ($this->claimCheckerManagers as $id => $checkerManager) {
            $data['checker']['claim_checker_managers'][$id] = [];
            foreach ($checkerManager->getCheckers() as $checker) {
                $data['checker']['claim_checker_managers'][$id][] = [
                    'claim' => $checker->supportedClaim(),
                ];
            }
        }
    }

    private function collectSupportedClaimCheckers(array &$data): void
    {
        $data['checker']['claim_checkers'] = [];
        if (null !== $this->claimCheckerManagerFactory) {
            $aliases = $this->claimCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $data['checker']['claim_checkers'][$alias] = [
                    'claim' => $checker->supportedClaim(),
                ];
            }
        }
    }

    private function collectEvents(array &$data): void
    {
        $data['checker']['events'] = [
            'header_check_success' => $this->headerCheckedSuccesses,
            'header_check_failure' => $this->headerCheckedFailures,
            'claim_check_success' => $this->claimCheckedSuccesses,
            'claim_check_failure' => $this->claimCheckedFailures,
        ];
    }
}

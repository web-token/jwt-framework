<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckerCollector implements Collector
{
    /**
     * @var ClaimCheckerManagerFactory|null
     */
    private $claimCheckerManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory|null
     */
    private $headerCheckerManagerFactory;

    /**
     * CheckerCollector constructor.
     */
    public function __construct(?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory = null)
    {
        $this->claimCheckerManagerFactory = $claimCheckerManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectHeaderCheckerManagers($data);
        $this->collectSupportedHeaderCheckers($data);
        $this->collectClaimCheckerManagers($data);
        $this->collectSupportedClaimCheckers($data);
    }

    private function collectHeaderCheckerManagers(array &$data)
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

    private function collectSupportedHeaderCheckers(array &$data)
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

    private function collectClaimCheckerManagers(array &$data)
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

    private function collectSupportedClaimCheckers(array &$data)
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

    /**
     * @var HeaderCheckerManager[]
     */
    private $headerCheckerManagers = [];

    public function addHeaderCheckerManager(string $id, HeaderCheckerManager $headerCheckerManager)
    {
        $this->headerCheckerManagers[$id] = $headerCheckerManager;
    }

    /**
     * @var ClaimCheckerManager[]
     */
    private $claimCheckerManagers = [];

    public function addClaimCheckerManager(string $id, ClaimCheckerManager $claimCheckerManager)
    {
        $this->claimCheckerManagers[$id] = $claimCheckerManager;
    }
}

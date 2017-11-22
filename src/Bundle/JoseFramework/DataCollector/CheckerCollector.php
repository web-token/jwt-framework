<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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

final class CheckerCollector implements Collector
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
     *
     * @param ClaimCheckerManagerFactory|null  $claimCheckerManagerFactory
     * @param HeaderCheckerManagerFactory|null $headerCheckerManagerFactory
     */
    public function __construct(?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null, ?HeaderCheckerManagerFactory $headerCheckerManagerFactory = null)
    {
        $this->claimCheckerManagerFactory = $claimCheckerManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectSupportedHeaderCheckers($data);
        $this->collectSupportedClaimCheckers($data);
    }

    public function name(): string
    {
        return 'checker';
    }

    /**
     * @return HeaderCheckerManager[]
     */
    public function getHeaderCheckerManagers(): array
    {
        return $this->headerCheckerManagers;
    }

    /**
     * @return ClaimCheckerManager[]
     */
    public function getClaimCheckerManagers(): array
    {
        return $this->claimCheckerManagers;
    }

    /**
     * @param array $data
     *
     * @return array
     */
    public function getHeaderCheckers(array $data): array
    {
        return $data['header_checkers'];
    }

    /**
     * @param array $data
     *
     * @return array
     */
    public function getClaimCheckers(array $data): array
    {
        return $data['claim_checkers'];
    }

    /**
     * @param array $data
     */
    private function collectSupportedHeaderCheckers(array &$data)
    {
        $data['header_checkers'] = [];
        if (null !== $this->headerCheckerManagerFactory) {
            $aliases = $this->headerCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $data['header_checkers'][$alias] = [
                    'header' => $checker->supportedHeader(),
                    'protected' => $checker->protectedHeaderOnly(),
                ];
            }
        }
    }

    /**
     * @param array $data
     */
    private function collectSupportedClaimCheckers(array &$data)
    {
        $data['claim_checkers'] = [];
        if (null !== $this->headerCheckerManagerFactory) {
            $aliases = $this->claimCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $data['claim_checkers'][$alias] = [
                    'claim' => $checker->supportedClaim(),
                ];
            }
        }
    }

    /**
     * @var HeaderCheckerManager[]
     */
    private $headerCheckerManagers = [];

    /**
     * @param string               $id
     * @param HeaderCheckerManager $headerCheckerManager
     */
    public function addHeaderCheckerManager(string $id, HeaderCheckerManager $headerCheckerManager)
    {
        $this->headerCheckerManagers[$id] = $headerCheckerManager;
    }

    /**
     * @var ClaimCheckerManager[]
     */
    private $claimCheckerManagers = [];

    /**
     * @param string              $id
     * @param ClaimCheckerManager $claimCheckerManager
     */
    public function addClaimCheckerManager(string $id, ClaimCheckerManager $claimCheckerManager)
    {
        $this->claimCheckerManagers[$id] = $claimCheckerManager;
    }
}

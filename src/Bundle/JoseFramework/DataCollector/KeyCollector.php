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

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

class KeyCollector implements Collector
{
    /**
     * @var null|KeyAnalyzerManager
     */
    private $jwkAnalyzerManager;

    /**
     * @var null|KeysetAnalyzerManager
     */
    private $jwksetAnalyzerManager;

    /**
     * @var JWK[]
     */
    private $jwks = [];

    /**
     * @var JWKSet[]
     */
    private $jwksets = [];

    public function __construct(?KeyAnalyzerManager $jwkAnalyzerManager = null, ?KeysetAnalyzerManager $jwksetAnalyzerManager = null)
    {
        $this->jwkAnalyzerManager = $jwkAnalyzerManager;
        $this->jwksetAnalyzerManager = $jwksetAnalyzerManager;
    }

    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectJWK($data);
        $this->collectJWKSet($data);
    }

    public function addJWK(string $id, JWK $jwk): void
    {
        $this->jwks[$id] = $jwk;
    }

    public function addJWKSet(string $id, JWKSet $jwkset): void
    {
        $this->jwksets[$id] = $jwkset;
    }

    private function collectJWK(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwk'] = [];
        foreach ($this->jwks as $id => $jwk) {
            $data['key']['jwk'][$id] = [
                'jwk' => $cloner->cloneVar($jwk),
                'analyze' => null === $this->jwkAnalyzerManager ? [] : $this->jwkAnalyzerManager->analyze($jwk),
            ];
        }
    }

    private function collectJWKSet(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwkset'] = [];
        foreach ($this->jwksets as $id => $jwkset) {
            $analyze = [];
            $analyzeJWKSet = new MessageBag();
            if (null !== $this->jwkAnalyzerManager) {
                foreach ($jwkset as $kid => $jwk) {
                    $analyze[$kid] = $this->jwkAnalyzerManager->analyze($jwk);
                }
            }
            if (null !== $this->jwksetAnalyzerManager) {
                $analyzeJWKSet = $this->jwksetAnalyzerManager->analyze($jwkset);
            }
            $data['key']['jwkset'][$id] = [
                'jwkset' => $cloner->cloneVar($jwkset),
                'analyze' => $analyze,
                'analyze_jwkset' => $analyzeJWKSet,
            ];
        }
    }
}

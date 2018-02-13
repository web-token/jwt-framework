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

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyAnalyzer\KeyAnalyzerManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class KeyCollector implements Collector
{
    /**
     * @var KeyAnalyzerManager|null
     */
    private $jwkAnalyzerManager;

    /**
     * KeyCollector constructor.
     *
     * @param KeyAnalyzerManager|null $jwkAnalyzerManager
     */
    public function __construct(?KeyAnalyzerManager $jwkAnalyzerManager = null)
    {
        $this->jwkAnalyzerManager = $jwkAnalyzerManager;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(array &$data, Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectJWK($data);
        $this->collectJWKSet($data);
    }

    /**
     * @param array $data
     */
    private function collectJWK(array &$data)
    {
        $data['key']['jwk'] = [];
        foreach ($this->jwks as $id => $jwk) {
            $data['key']['jwk'][$id] = [
                'jwk'     => $jwk,
                'analyze' => null === $this->jwkAnalyzerManager ? [] : $this->jwkAnalyzerManager->analyze($jwk),
            ];
        }
    }

    /**
     * @param array $data
     */
    private function collectJWKSet(array &$data)
    {
        $data['key']['jwkset'] = [];
        foreach ($this->jwksets as $id => $jwkset) {
            $analyze = [];
            if (null !== $this->jwkAnalyzerManager) {
                foreach ($jwkset as $kid => $jwk) {
                    $analyze[$kid] = $this->jwkAnalyzerManager->analyze($jwk);
                }
            }
            $data['key']['jwkset'][$id] = [
                'jwkset'  => $jwkset,
                'analyze' => $analyze,
            ];
        }
    }

    /**
     * @var JWK[]
     */
    private $jwks = [];

    /**
     * @param string $id
     * @param JWK    $jwk
     */
    public function addJWK(string $id, JWK $jwk)
    {
        $this->jwks[$id] = $jwk;
    }

    /**
     * @var JWKSet[]
     */
    private $jwksets = [];

    /**
     * @param string $id
     * @param JWKSet $jwkset
     */
    public function addJWKSet(string $id, JWKSet $jwkset)
    {
        $this->jwksets[$id] = $jwkset;
    }
}

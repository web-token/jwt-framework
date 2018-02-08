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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

/**
 * Class KeyAnalyzerManager.
 */
class KeyAnalyzerManager
{
    /**
     * @var KeyAnalyzer[]
     */
    private $analyzers = [];

    /**
     * @param KeyAnalyzer $analyzer
     *
     * @return KeyAnalyzerManager
     */
    public function add(KeyAnalyzer $analyzer): self
    {
        $this->analyzers[] = $analyzer;

        return $this;
    }

    /**
     * @param JWK $jwk
     *
     * @return MessageBag
     */
    public function analyze(JWK $jwk): MessageBag
    {
        $bag = new MessageBag();
        foreach ($this->analyzers as $analyzer) {
            $analyzer->analyze($jwk, $bag);
        }

        return $bag;
    }
}

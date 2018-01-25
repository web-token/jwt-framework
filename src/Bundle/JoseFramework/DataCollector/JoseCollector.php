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

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

final class JoseCollector extends DataCollector
{
    /**
     * @var Collector[]
     */
    private $collectors = [];

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Exception $exception = null)
    {
        foreach ($this->collectors as $collector) {
            $collector->collect($this->data, $request, $response, $exception);
        }
    }

    /**
     * @param Collector $collector
     */
    public function add(Collector $collector)
    {
        $this->collectors[] = $collector;
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jose_collector';
    }

    /**
     * @return array
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * {@inheritdoc}
     */
    public function reset()
    {
        $this->data = [];
    }
}

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

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\VarDumper\Cloner\Data;
use Throwable;

class JoseCollector extends DataCollector
{
    /**
     * @var Collector[]
     */
    private $collectors = [];

    public function collect(Request $request, Response $response, ?Throwable $exception = null): void
    {
        foreach ($this->collectors as $collector) {
            $collector->collect($this->data, $request, $response, $exception);
        }
    }

    public function add(Collector $collector): void
    {
        $this->collectors[] = $collector;
    }

    public function getName()
    {
        return 'jose_collector';
    }

    /**
     * @return array|Data
     */
    public function getData()
    {
        return $this->data;
    }

    public function reset(): void
    {
        $this->data = [];
    }
}

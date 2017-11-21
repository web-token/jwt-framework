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
        $this->collectors[$collector->name()] = $collector;
    }

    /**
     * @param string $name
     * @param string $method
     */
    public function get(string $name, string $method)
    {
        if (!array_key_exists($name, $this->collectors)) {
            throw new \InvalidArgumentException(sprintf('No collector with name "%s".', $name));
        }
        $collector = $this->collectors[$name];
        if (!method_exists($collector, $method)) {
            throw new \InvalidArgumentException(sprintf('The collector with name "%s" has no method "%s".', $name, $method));
        }

        return $collector->$method($this->data);
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jose_collector';
    }
}

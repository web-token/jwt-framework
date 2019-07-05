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

namespace Jose\Easy;

use ArrayIterator;
use Countable;
use IteratorAggregate;

class ParameterBag implements IteratorAggregate, Countable
{
    private $parameters = [];

    public function all(): array
    {
        return $this->parameters;
    }

    public function keys(): array
    {
        return array_keys($this->parameters);
    }

    public function replace(array $parameters): void
    {
        $this->parameters = $parameters;
    }

    public function add(array $parameters): void
    {
        $this->parameters = array_replace($this->parameters, $parameters);
    }

    /**
     * @param mixed $default
     * @param mixed $key
     *
     * @return mixed
     */
    public function get($key, $default = null)
    {
        return \array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

    /**
     * @param mixed $value The value
     * @param mixed $key
     */
    public function set($key, $value): void
    {
        $this->parameters[$key] = $value;
    }

    public function has($key): bool
    {
        return \array_key_exists($key, $this->parameters);
    }

    public function remove($key): void
    {
        unset($this->parameters[$key]);
    }

    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->parameters);
    }

    public function count(): int
    {
        return \count($this->parameters);
    }
}

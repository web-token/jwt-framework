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

namespace Jose\Easy;

use function array_key_exists;
use ArrayIterator;
use function call_user_func_array;
use function count;
use Countable;
use InvalidArgumentException;
use IteratorAggregate;

class ParameterBag implements IteratorAggregate, Countable
{
    /**
     * @var array
     */
    private $parameters = [];

    /**
     * @return mixed
     */
    public function __call(string $name, array $arguments)
    {
        if (method_exists($this, $name)) {
            return call_user_func_array([$this, $name], $arguments);
        }

        if (0 === count($arguments)) {
            return $this->get($name);
        }
        array_unshift($arguments, $name);

        return call_user_func_array([$this, 'set'], $arguments);
    }

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

    /**
     * @throws InvalidArgumentException if the parameters are invalid
     */
    public function add(array $parameters): void
    {
        /** @var null|array $replaced */
        $replaced = array_replace($this->parameters, $parameters);
        if (null === $replaced) {
            throw new InvalidArgumentException('Invalid parameters');
        }
        $this->parameters = $replaced;
    }

    /**
     * @throws InvalidArgumentException if the selected parameter is missing
     *
     * @return mixed
     */
    public function get(string $key)
    {
        if (!array_key_exists($key, $this->parameters)) {
            throw new InvalidArgumentException(sprintf('Parameter "%s" is missing', $key));
        }

        return $this->parameters[$key];
    }

    /**
     * @param mixed $value The value
     */
    public function set(string $key, $value): void
    {
        $this->parameters[$key] = $value;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->parameters);
    }

    public function remove(string $key): void
    {
        unset($this->parameters[$key]);
    }

    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->parameters);
    }

    public function count(): int
    {
        return count($this->parameters);
    }
}

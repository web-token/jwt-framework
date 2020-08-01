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

use Jose\Component\Core\Algorithm;
use Throwable;

final class AlgorithmProvider
{
    /**
     * @var string[]
     */
    private $algorithmClasses;

    /**
     * @var Algorithm[]
     */
    private $algorithms = [];

    public function __construct(array $algorithmClasses)
    {
        $this->algorithmClasses = $algorithmClasses;
        foreach ($algorithmClasses as $algorithmClass) {
            $this->addClass($algorithmClass);
        }
    }

    public function getAlgorithmClasses(): array
    {
        return $this->algorithmClasses;
    }

    public function getAvailableAlgorithms(): array
    {
        return $this->algorithms;
    }

    private function addClass(string $algorithmClass): void
    {
        if (class_exists($algorithmClass)) {
            try {
                $this->algorithms[] = new $algorithmClass();
            } catch (Throwable $throwable) {
                //does nothing
            }
        }
    }
}

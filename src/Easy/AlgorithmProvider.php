<?php

declare(strict_types=1);

namespace Jose\Easy;

use Jose\Component\Core\Algorithm;
use Throwable;

final class AlgorithmProvider
{
    /**
     * @var string[]
     */
    private array $algorithmClasses;

    /**
     * @var Algorithm[]
     */
    private array $algorithms = [];

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
            } catch (Throwable) {
                //does nothing
            }
        }
    }
}

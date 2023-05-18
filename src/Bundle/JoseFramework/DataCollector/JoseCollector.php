<?php

declare(strict_types=1);

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
    private array $collectors = [];

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

    public function getName(): string
    {
        return 'jose_collector';
    }

    /**
     * @return array<string, mixed>|Data
     */
    public function getData(): array|Data
    {
        return $this->data;
    }

    public function reset(): void
    {
        $this->data = [];
    }
}

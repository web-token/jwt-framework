<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DataCollector;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

interface Collector
{
    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void;
}

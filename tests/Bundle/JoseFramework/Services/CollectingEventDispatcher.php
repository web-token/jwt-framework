<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Services;

use Psr\EventDispatcher\EventDispatcherInterface;
use function count;

/**
 * Keeps every dispatched event so that the decorators of the bundle can be observed.
 *
 * @internal
 */
final class CollectingEventDispatcher implements EventDispatcherInterface
{
    /**
     * @var object[]
     */
    private array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }

    /**
     * @return object[]
     */
    public function events(): array
    {
        return $this->events;
    }

    public function lastEvent(): ?object
    {
        return $this->events[count($this->events) - 1] ?? null;
    }
}

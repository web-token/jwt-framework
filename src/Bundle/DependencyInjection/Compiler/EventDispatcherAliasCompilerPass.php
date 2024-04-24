<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DependencyInjection\Compiler;

use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final readonly class EventDispatcherAliasCompilerPass implements CompilerPassInterface
{
    #[Override]
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition('event_dispatcher') || $container->hasAlias(EventDispatcherInterface::class)) {
            return;
        }

        $container->setAlias(EventDispatcherInterface::class, 'event_dispatcher');
    }
}

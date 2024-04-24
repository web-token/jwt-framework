<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Routing;

use Override;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use function assert;

final class JWKSetLoader implements LoaderInterface
{
    private readonly RouteCollection $routes;

    private null|LoaderResolverInterface $resolver = null;

    public function __construct()
    {
        $this->routes = new RouteCollection();
    }

    public function add(string $pattern, string $name): void
    {
        $defaults = [
            '_controller' => $name,
        ];
        $route = new Route($pattern, $defaults);
        $this->routes->add(sprintf('jwkset_%s', $name), $route);
    }

    #[Override]
    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        return $this->routes;
    }

    #[Override]
    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'jwkset';
    }

    #[Override]
    public function getResolver(): LoaderResolverInterface
    {
        assert($this->resolver !== null, 'Resolver is not set.');
        return $this->resolver;
    }

    #[Override]
    public function setResolver(LoaderResolverInterface $resolver): void
    {
        $this->resolver = $resolver;
    }
}

<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Routing;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

final class JWKSetLoader implements LoaderInterface
{
    private RouteCollection $routes;

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

    /**
     * {@inheritdoc}
     */
    public function load($resource, $type = null): RouteCollection
    {
        return $this->routes;
    }

    /**
     * {@inheritdoc}
     */
    public function supports($resource, $type = null): bool
    {
        return $type === 'jwkset';
    }

    public function getResolver(): void
    {
    }

    public function setResolver(LoaderResolverInterface $resolver): void
    {
    }
}

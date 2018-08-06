<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Routing;

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

class JWKSetLoader implements LoaderInterface
{
    /**
     * @var RouteCollection
     */
    private $routes;

    /**
     * JWKSetLoader Constructor.
     */
    public function __construct()
    {
        $this->routes = new RouteCollection();
    }

    public function add(string $pattern, string $name)
    {
        $controller_id = \sprintf('%s:getAction', $name);
        $defaults = ['_controller' => $controller_id];
        $route = new Route($pattern, $defaults);
        $this->routes->add(\sprintf('jwkset_%s', $name), $route);
    }

    public function load($resource, $type = null)
    {
        return $this->routes;
    }

    public function supports($resource, $type = null)
    {
        return 'jwkset' === $type;
    }

    public function getResolver()
    {
    }

    public function setResolver(LoaderResolverInterface $resolver)
    {
    }
}

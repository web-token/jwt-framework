<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Composer\Autoload\ClassLoader;
use Doctrine\Common\Annotations\AnnotationRegistry;

/*
 * @var ClassLoader
 */
$loader = require __DIR__.'/../../vendor/autoload.php';

//AnnotationRegistry::registerLoader([$loader, 'loadClass']);

return $loader;

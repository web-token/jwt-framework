<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

use Throwable;

/**
 * Marker interface implemented by every exception thrown by this library.
 *
 * It allows a single catch block to handle any failure reported by the framework:
 *
 *     try {
 *         $jws = $jwsLoader->loadAndVerifyWithKeySet($token, $jwkset, $signature);
 *     } catch (JoseException $e) {
 *         // the original cause, when there is one, is available through $e->getPrevious()
 *     }
 *
 * Every implementation extends the SPL exception that was thrown before version 4.3.0, hence the catch
 * blocks written for previous versions keep matching.
 */
interface JoseException extends Throwable
{
}

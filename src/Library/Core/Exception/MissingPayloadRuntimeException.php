<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown by the JWS builder when no payload was set.
 *
 * It extends RuntimeException, the SPL class thrown by that builder before version 4.3.0. Catch
 * MissingPayloadException to handle the JWE builder the same way.
 */
final class MissingPayloadRuntimeException extends RuntimeException implements MissingPayloadException
{
}

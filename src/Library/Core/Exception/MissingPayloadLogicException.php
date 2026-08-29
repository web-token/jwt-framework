<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown by the JWE builder when no payload was set.
 *
 * It extends LogicException, the SPL class thrown by that builder before version 4.3.0. Catch
 * MissingPayloadException to handle the JWS builder the same way.
 */
final class MissingPayloadLogicException extends LogicException implements MissingPayloadException
{
}

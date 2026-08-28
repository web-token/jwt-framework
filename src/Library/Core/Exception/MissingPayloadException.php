<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Implemented by the exceptions thrown when a builder is asked to build a token without a payload.
 *
 * Before version 4.3.0 the JWS builder reported that failure with a RuntimeException and the JWE builder
 * with a LogicException. Those two SPL parents cannot be merged without breaking the existing catch
 * blocks, hence the two implementations MissingPayloadRuntimeException and MissingPayloadLogicException.
 * Catching this interface handles both. They are merged into a single class in version 5.0.0.
 */
interface MissingPayloadException extends JoseException
{
}

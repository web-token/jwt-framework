<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

/**
 * Marks a value of the claims given to the Issuer as selectively disclosable.
 *
 * As the value of an object member, the marker makes that member selectively disclosable (RFC 9901 section 4.2.1); as
 * an element of an array, it makes that element selectively disclosable (section 4.2.2). The marked value may contain
 * other markers: its Disclosure is then created after the Disclosures it contains, which is how the recursive
 * Disclosures of section 4.2.6 are built.
 *
 *     $claims = [
 *         'iss' => 'https://issuer.example.com',
 *         'sub' => 'user_42',
 *         'given_name' => new Disclosable('John'),
 *         'address' => new Disclosable([
 *             'locality' => new Disclosable('Anytown'),
 *             'country' => 'US',
 *         ]),
 *         'nationalities' => [new Disclosable('US'), new Disclosable('DE')],
 *     ];
 *
 * When no salt is given, the Issuer generates one. A given salt must be unique within the SD-JWT and drawn from a
 * cryptographically secure random source, with at least 128 bits of entropy (section 9.3): it is meant for
 * reproducible tests and for applications that derive their salts, not for constant values.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2
 */
final readonly class Disclosable
{
    public function __construct(
        private mixed $value,
        private ?string $salt = null
    ) {
    }

    /**
     * The value that is disclosed, which may contain other markers.
     */
    public function getValue(): mixed
    {
        return $this->value;
    }

    /**
     * The salt of the Disclosure, or null when the Issuer generates it.
     */
    public function getSalt(): ?string
    {
        return $this->salt;
    }
}

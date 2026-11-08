<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Component\Length;
use SpomkyLabs\Pki\ASN1\DERData;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use function array_key_exists;
use function count;
use function ltrim;
use function ord;
use function sprintf;
use function strlen;

/**
 * @internal
 */
final class RSAKey
{
    /**
     * The limits of OpenSSL, in bytes: a modulus of 16384 bits at most, and a public exponent no longer than the
     * modulus and of 64 bits at most above 3072 bits. RSA-PSS and RSAES compute the public operation in PHP, at a cost
     * set by these lengths.
     */
    private const MAX_MODULUS_LENGTH = 2048;

    private const SMALL_MODULUS_LENGTH = 384;

    private const MAX_PUBLIC_EXPONENT_LENGTH = 8;

    private null|Sequence $sequence = null;

    private readonly array $values;

    private ?BigInteger $modulus = null;

    private readonly int $modulus_length;

    private ?BigInteger $public_exponent = null;

    private bool $private_big_integers_populated = false;

    private ?BigInteger $private_exponent = null;

    /**
     * @var BigInteger[]
     */
    private array $primes = [];

    /**
     * @var BigInteger[]
     */
    private array $exponents = [];

    private ?BigInteger $coefficient = null;

    private function __construct(JWK $data)
    {
        $this->values = $data->all();
        $modulusLength = $this->getMemberLength('n');
        if ($modulusLength > self::MAX_MODULUS_LENGTH) {
            throw new InvalidArgumentException('The key parameter "n" is too long.');
        }
        $limit = $modulusLength > self::SMALL_MODULUS_LENGTH ? self::MAX_PUBLIC_EXPONENT_LENGTH : $modulusLength;
        if ($this->getMemberLength('e') > $limit) {
            throw new InvalidArgumentException('The key parameter "e" is too long.');
        }
        $this->modulus_length = $modulusLength;
    }

    public static function createFromJWK(JWK $jwk): self
    {
        return new self($jwk);
    }

    public function getModulus(): BigInteger
    {
        return $this->modulus ??= $this->convertBase64StringToBigInteger($this->values['n']);
    }

    public function getModulusLength(): int
    {
        return $this->modulus_length;
    }

    public function getExponent(): BigInteger
    {
        $d = $this->getPrivateExponent();
        if ($d !== null) {
            return $d;
        }

        return $this->getPublicExponent();
    }

    public function getPublicExponent(): BigInteger
    {
        return $this->public_exponent ??= $this->convertBase64StringToBigInteger($this->values['e']);
    }

    public function getPrivateExponent(): ?BigInteger
    {
        $this->populatePrivateBigIntegers();

        return $this->private_exponent;
    }

    /**
     * @return BigInteger[]
     */
    public function getPrimes(): array
    {
        $this->populatePrivateBigIntegers();

        return $this->primes;
    }

    /**
     * @return BigInteger[]
     */
    public function getExponents(): array
    {
        $this->populatePrivateBigIntegers();

        return $this->exponents;
    }

    public function getCoefficient(): ?BigInteger
    {
        $this->populatePrivateBigIntegers();

        return $this->coefficient;
    }

    public function isPublic(): bool
    {
        return ! array_key_exists('d', $this->values);
    }

    public static function toPublic(self $private): self
    {
        $data = $private->toArray();
        $keys = ['p', 'd', 'q', 'dp', 'dq', 'qi'];
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                unset($data[$key]);
            }
        }

        return new self(new JWK($data));
    }

    public function toArray(): array
    {
        return $this->values;
    }

    public function toPEM(): string
    {
        if (array_key_exists('d', $this->values)) {
            $zero = Integer::create(0);
            $this->sequence = Sequence::create(
                Integer::create(0),
                RSAEncryptionAlgorithmIdentifier::create()->toASN1(),
                OctetString::create(
                    Sequence::create(
                        $zero,
                        $this->fromBase64ToInteger($this->values['n']),
                        $this->fromBase64ToInteger($this->values['e']),
                        $this->fromBase64ToInteger($this->values['d']),
                        isset($this->values['p']) ? $this->fromBase64ToInteger($this->values['p']) : $zero,
                        isset($this->values['q']) ? $this->fromBase64ToInteger($this->values['q']) : $zero,
                        isset($this->values['dp']) ? $this->fromBase64ToInteger($this->values['dp']) : $zero,
                        isset($this->values['dq']) ? $this->fromBase64ToInteger($this->values['dq']) : $zero,
                        isset($this->values['qi']) ? $this->fromBase64ToInteger($this->values['qi']) : $zero,
                    )->toDER()
                )
            );

            return PEM::create(PEM::TYPE_PRIVATE_KEY, $this->sequence->toDER())
                ->string();
        }
        $this->sequence = Sequence::create(
            RSAEncryptionAlgorithmIdentifier::create()->toASN1(),
            BitString::create(
                Sequence::create(
                    $this->fromBase64ToInteger($this->values['n']),
                    $this->fromBase64ToInteger($this->values['e'])
                )->toDER()
            )
        );

        return PEM::create(PEM::TYPE_PUBLIC_KEY, $this->sequence->toDER())
            ->string();
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem. Operation with primes 'p' and 'q' is appox. 2x faster.
     */
    public static function exponentiate(self $key, BigInteger $c): BigInteger
    {
        if ($c->compare(BigInteger::createFromDecimal(0)) < 0 || $c->compare($key->getModulus()) > 0) {
            throw new RuntimeException();
        }
        if ($key->isPublic() || $key->getCoefficient() === null || count($key->getPrimes()) === 0 || count(
            $key->getExponents()
        ) === 0) {
            return $c->modPow($key->getExponent(), $key->getModulus());
        }

        $p = $key->getPrimes()[0];
        $q = $key->getPrimes()[1];
        $dP = $key->getExponents()[0];
        $dQ = $key->getExponents()[1];
        $qInv = $key->getCoefficient();

        $m1 = $c->modPow($dP, $p);
        $m2 = $c->modPow($dQ, $q);
        $h = $qInv->multiply($m1->subtract($m2)->add($p))
            ->mod($p);

        return $m2->add($h->multiply($q));
    }

    private function populatePrivateBigIntegers(): void
    {
        if ($this->private_big_integers_populated || $this->isPublic()) {
            return;
        }
        $this->private_exponent = $this->convertBase64StringToBigInteger($this->values['d']);

        if (array_key_exists('p', $this->values) && array_key_exists('q', $this->values)) {
            $this->primes = [
                $this->convertBase64StringToBigInteger($this->values['p']),
                $this->convertBase64StringToBigInteger($this->values['q']),
            ];
            if (array_key_exists('dp', $this->values) && array_key_exists('dq', $this->values) && array_key_exists(
                'qi',
                $this->values
            )) {
                $this->exponents = [
                    $this->convertBase64StringToBigInteger($this->values['dp']),
                    $this->convertBase64StringToBigInteger($this->values['dq']),
                ];
                $this->coefficient = $this->convertBase64StringToBigInteger($this->values['qi']);
            }
        }
        $this->private_big_integers_populated = true;
    }

    private function getMemberLength(string $member): int
    {
        $value = Base64UrlSafe::decodeNoPadding($this->values[$member]);
        if ($value === '') {
            throw new InvalidArgumentException(sprintf('The key parameter "%s" is invalid.', $member));
        }

        return strlen(ltrim($value, "\0"));
    }

    private function convertBase64StringToBigInteger(string $value): BigInteger
    {
        return BigInteger::createFromBinaryString(Base64UrlSafe::decodeNoPadding($value));
    }

    /**
     * Writes the DER integer from the bytes of the member, without converting it into a big integer.
     */
    private function fromBase64ToInteger(string $value): DERData
    {
        $value = Base64UrlSafe::decodeNoPadding($value);
        if ($value === '') {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        $value = ltrim($value, "\0");
        if ($value === '' || ord($value[0]) > 0x7F) {
            $value = "\0" . $value;
        }

        return DERData::create("\x02" . Length::create(strlen($value))->toDER() . $value);
    }
}

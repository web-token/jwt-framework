<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use RuntimeException;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\BitString;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPrivateKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\RSA\RSAPublicKey;
use function array_key_exists;
use function count;
use function is_array;

/**
 * @internal
 */
final class RSAKey
{
    private null|Sequence $sequence = null;

    private readonly array $values;

    private BigInteger $modulus;

    private int $modulus_length;

    private BigInteger $public_exponent;

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
        $this->populateBigIntegers();
    }

    public static function createFromJWK(JWK $jwk): self
    {
        return new self($jwk);
    }

    public function getModulus(): BigInteger
    {
        return $this->modulus;
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
        return $this->public_exponent;
    }

    public function getPrivateExponent(): ?BigInteger
    {
        return $this->private_exponent;
    }

    /**
     * @return BigInteger[]
     */
    public function getPrimes(): array
    {
        return $this->primes;
    }

    /**
     * @return BigInteger[]
     */
    public function getExponents(): array
    {
        return $this->exponents;
    }

    public function getCoefficient(): ?BigInteger
    {
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
            $this->sequence = Sequence::create(
                Integer::create(0),
                RSAEncryptionAlgorithmIdentifier::create()->toASN1(),
                OctetString::create(
                    RSAPrivateKey::create(
                        $this->fromBase64ToInteger($this->values['n']),
                        $this->fromBase64ToInteger($this->values['e']),
                        $this->fromBase64ToInteger($this->values['d']),
                        isset($this->values['p']) ? $this->fromBase64ToInteger($this->values['p']) : '0',
                        isset($this->values['q']) ? $this->fromBase64ToInteger($this->values['q']) : '0',
                        isset($this->values['dp']) ? $this->fromBase64ToInteger($this->values['dp']) : '0',
                        isset($this->values['dq']) ? $this->fromBase64ToInteger($this->values['dq']) : '0',
                        isset($this->values['qi']) ? $this->fromBase64ToInteger($this->values['qi']) : '0',
                    )->toDER()
                )
            );

            return PEM::create(PEM::TYPE_PRIVATE_KEY, $this->sequence->toDER())
                ->string();
        }
        $this->sequence = Sequence::create(
            RSAEncryptionAlgorithmIdentifier::create()->toASN1(),
            BitString::create(
                RSAPublicKey::create(
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
     *
     * The input must lie between 0 and n - 1, as RFC 8017 requires of the representatives given to RSAEP, RSADP,
     * RSASP1 and RSAVP1 (sections 5.1 and 5.2). The modulus itself is rejected: it is congruent to 0.
     *
     * Private key operations are blinded. The private key is applied to c * r^e mod n, where r is a fresh random
     * number coprime to n, and the result is multiplied by r^-1 mod n. The integers handled by the exponentiation and
     * by the CRT recombination are thus unrelated to c, which the sender of a token chooses, and so is the time they
     * take. Without it, the time needed to reject a token tells on which side of the prime q its plaintext lies.
     */
    public static function exponentiate(self $key, BigInteger $c): BigInteger
    {
        if ($c->compare(BigInteger::createFromDecimal(0)) < 0 || $c->compare($key->getModulus()) >= 0) {
            throw new RuntimeException();
        }
        if ($key->isPublic()) {
            return $c->modPow($key->getExponent(), $key->getModulus());
        }

        $n = $key->getModulus();
        $r = self::blindingFactor($n);
        $blinded = $c->multiply($r->modPow($key->getPublicExponent(), $n))
            ->mod($n);

        return self::exponentiateWithPrivateKey($key, $blinded)
            ->multiply($r->modInverse($n))
            ->mod($n);
    }

    /**
     * Draws the blinding factor: a uniformly random number in [1, n - 1] that is coprime to n.
     */
    private static function blindingFactor(BigInteger $n): BigInteger
    {
        $one = BigInteger::createFromDecimal(1);
        do {
            $r = BigInteger::random($n->subtract($one));
        } while (! $r->gcd($n)->equals($one));

        return $r;
    }

    private static function exponentiateWithPrivateKey(self $key, BigInteger $c): BigInteger
    {
        if ($key->getCoefficient() === null || count($key->getPrimes()) === 0 || count($key->getExponents()) === 0) {
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

    private function populateBigIntegers(): void
    {
        $this->modulus = $this->convertBase64StringToBigInteger($this->values['n']);
        $this->modulus_length = mb_strlen($this->getModulus()->toBytes(), '8bit');
        $this->public_exponent = $this->convertBase64StringToBigInteger($this->values['e']);

        if (! $this->isPublic()) {
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
        }
    }

    private function convertBase64StringToBigInteger(string $value): BigInteger
    {
        return BigInteger::createFromBinaryString(Base64UrlSafe::decodeNoPadding($value));
    }

    private function fromBase64ToInteger(string $value): string
    {
        $unpacked = unpack('H*', Base64UrlSafe::decodeNoPadding($value));
        if (! is_array($unpacked) || count($unpacked) === 0) {
            throw new InvalidArgumentException('Unable to get the private key');
        }

        return \Brick\Math\BigInteger::fromBase(current($unpacked), 16)->toBase(10);
    }
}

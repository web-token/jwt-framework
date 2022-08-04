<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use function array_key_exists;
use function count;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\NullObject;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;
use const PHP_EOL;
use RuntimeException;

/**
 * @internal
 */
final class RSAKey
{
    private Sequence $sequence;

    private readonly bool $private;

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
        $this->sequence = new Sequence();
        $this->values = $data->all();
        $this->populateBigIntegers();
        $this->private = array_key_exists('d', $this->values);
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
        $this->sequence = new Sequence();
        if (array_key_exists('d', $this->values)) {
            $this->initPrivateKey();
        } else {
            $this->initPublicKey();
        }
        $result = '-----BEGIN ' . ($this->private ? 'RSA PRIVATE' : 'PUBLIC') . ' KEY-----' . PHP_EOL;
        $result .= chunk_split(base64_encode($this->sequence->getBinary()), 64, PHP_EOL);

        return $result . ('-----END ' . ($this->private ? 'RSA PRIVATE' : 'PUBLIC') . ' KEY-----' . PHP_EOL);
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
        return BigInteger::createFromBinaryString(Base64UrlSafe::decode($value));
    }

    private function initPublicKey(): void
    {
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->sequence->addChild($oid_sequence);
        $n = new Integer($this->fromBase64ToInteger($this->values['n']));
        $e = new Integer($this->fromBase64ToInteger($this->values['e']));
        $key_sequence = new Sequence();
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_bit_string = new BitString(bin2hex($key_sequence->getBinary()));
        $this->sequence->addChild($key_bit_string);
    }

    private function initPrivateKey(): void
    {
        $this->sequence->addChild(new Integer(0));
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->sequence->addChild($oid_sequence);
        $v = new Integer(0);
        $n = new Integer($this->fromBase64ToInteger($this->values['n']));
        $e = new Integer($this->fromBase64ToInteger($this->values['e']));
        $d = new Integer($this->fromBase64ToInteger($this->values['d']));
        $p = new Integer($this->fromBase64ToInteger($this->values['p']));
        $q = new Integer($this->fromBase64ToInteger($this->values['q']));
        $dp = array_key_exists('dp', $this->values) ? new Integer($this->fromBase64ToInteger(
            $this->values['dp']
        )) : new Integer(0);
        $dq = array_key_exists('dq', $this->values) ? new Integer($this->fromBase64ToInteger(
            $this->values['dq']
        )) : new Integer(0);
        $qi = array_key_exists('qi', $this->values) ? new Integer($this->fromBase64ToInteger(
            $this->values['qi']
        )) : new Integer(0);
        $key_sequence = new Sequence();
        $key_sequence->addChild($v);
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_sequence->addChild($d);
        $key_sequence->addChild($p);
        $key_sequence->addChild($q);
        $key_sequence->addChild($dp);
        $key_sequence->addChild($dq);
        $key_sequence->addChild($qi);
        $key_octet_string = new OctetString(bin2hex($key_sequence->getBinary()));
        $this->sequence->addChild($key_octet_string);
    }

    private function fromBase64ToInteger(string $value): string
    {
        $unpacked = unpack('H*', Base64UrlSafe::decode($value));
        if (! is_array($unpacked) || count($unpacked) === 0) {
            throw new InvalidArgumentException('Unable to get the private key');
        }

        return \Brick\Math\BigInteger::fromBase(current($unpacked), 16)->toBase(10);
    }
}

<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\JWK;
use SpomkyLabs\Pki\ASN1\DERData;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Asymmetric\RSAEncryptionAlgorithmIdentifier;
use function array_key_exists;
use function chr;
use function count;
use function extension_loaded;
use function is_string;
use function ltrim;
use function ord;
use function sprintf;
use function strlen;
use const OPENSSL_NO_PADDING;
use const STR_PAD_LEFT;

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

    /**
     * AlgorithmIdentifier of rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters, in DER.
     */
    private const RSA_ALGORITHM_IDENTIFIER = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";

    private null|Sequence $sequence = null;

    private readonly array $values;

    private ?BigInteger $modulus = null;

    private readonly int $modulusLength;

    private ?BigInteger $publicExponent = null;

    private bool $privateBigIntegersPopulated = false;

    private ?BigInteger $privateExponent = null;

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
            throw new InvalidKeyException('The key parameter "n" is too long.');
        }
        $limit = $modulusLength > self::SMALL_MODULUS_LENGTH ? self::MAX_PUBLIC_EXPONENT_LENGTH : $modulusLength;
        if ($this->getMemberLength('e') > $limit) {
            throw new InvalidKeyException('The key parameter "e" is too long.');
        }
        $this->modulusLength = $modulusLength;
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
        return $this->modulusLength;
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
        return $this->publicExponent ??= $this->convertBase64StringToBigInteger($this->values['e']);
    }

    public function getPrivateExponent(): ?BigInteger
    {
        $this->populatePrivateBigIntegers();

        return $this->privateExponent;
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
        $publicKey = self::encodeDER(
            0x30,
            $this->fromBase64ToInteger($this->values['n'])->toDER() . $this->fromBase64ToInteger(
                $this->values['e']
            )->toDER()
        );

        return PEM::create(
            PEM::TYPE_PUBLIC_KEY,
            self::encodeDER(0x30, self::RSA_ALGORITHM_IDENTIFIER . self::encodeDER(0x03, "\0" . $publicKey))
        )->string();
    }

    /**
     * Computes input^e mod n (RSAEP, RSAVP1) on big-endian strings as long as the modulus. OpenSSL computes it when the
     * extension is loaded, so that the cost does not depend on the brick/math calculator.
     */
    public static function applyPublicKey(self $key, string $input): string
    {
        $public = self::toPublic($key);
        if (strlen($input) !== $public->getModulusLength()) {
            throw new RuntimeException('The input must be as long as the modulus.');
        }
        if (! extension_loaded('openssl')) {
            $output = self::exponentiate($public, BigInteger::createFromBinaryString($input))->toBytes();

            return str_pad($output, $public->getModulusLength(), "\0", STR_PAD_LEFT);
        }
        $output = '';
        if (! openssl_public_encrypt($input, $output, $public->toPEM(), OPENSSL_NO_PADDING) || ! is_string($output)) {
            throw new RuntimeException('Unable to apply the public key.');
        }

        return $output;
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

    private function populatePrivateBigIntegers(): void
    {
        if ($this->privateBigIntegersPopulated || $this->isPublic()) {
            return;
        }
        $this->privateExponent = $this->convertBase64StringToBigInteger($this->values['d']);

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
        $this->privateBigIntegersPopulated = true;
    }

    private function getMemberLength(string $member): int
    {
        $value = Base64UrlSafe::decodeNoPadding($this->values[$member]);
        if ($value === '') {
            throw new InvalidKeyException(sprintf('The key parameter "%s" is invalid.', $member));
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
            throw new InvalidKeyException('Unable to get the private key');
        }
        $value = ltrim($value, "\0");
        if ($value === '' || ord($value[0]) > 0x7F) {
            $value = "\0" . $value;
        }

        return DERData::create(self::encodeDER(0x02, $value));
    }

    /**
     * Encodes a DER element without the big integers pki-framework uses for lengths: a public key is written for every
     * RSA public key operation.
     */
    private static function encodeDER(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return chr($tag) . chr($length) . $content;
        }
        $lengthOctets = ltrim(pack('N', $length), "\0");

        return chr($tag) . chr(0x80 | strlen($lengthOctets)) . $lengthOctets . $content;
    }
}

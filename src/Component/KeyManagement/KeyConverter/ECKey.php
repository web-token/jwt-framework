<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\KeyConverter;

use function array_key_exists;
use function count;
use FG\ASN1\ASNObject;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use InvalidArgumentException;
use function is_array;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * @internal
 */
final class ECKey
{
    private array $values = [];

    private function __construct(array $data)
    {
        $this->loadJWK($data);
    }

    public static function createFromPEM(string $pem): self
    {
        $data = self::loadPEM($pem);

        return new self($data);
    }

    public static function toPublic(self $private): self
    {
        $data = $private->toArray();
        if (array_key_exists('d', $data)) {
            unset($data['d']);
        }

        return new self($data);
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->values;
    }

    private static function loadPEM(string $data): array
    {
        $data = base64_decode(preg_replace('#-.*-|\r|\n#', '', $data) ?? '', true);
        $asnObject = ASNObject::fromBinary($data);
        if (! $asnObject instanceof Sequence) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $children = $asnObject->getChildren();
        if (self::isPKCS8($children)) {
            return self::loadPKCS8($children);
        }

        if (count($children) === 4) {
            return self::loadPrivatePEM($children);
        }
        if (count($children) === 2) {
            return self::loadPublicPEM($children);
        }

        throw new InvalidArgumentException('Unable to load the key.');
    }

    /**
     * @param ASNObject[] $children
     */
    private static function loadPKCS8(array $children): array
    {
        $oidList = $children[1]->getContent();
        if (! is_array($oidList) || count($oidList) !== 2) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $oid = $oidList[1];
        if (! $oid instanceof ObjectIdentifier) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $oid = $oid->getContent();
        if (! is_string($oid)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $data = $children[2]->getContent();
        if (! is_string($data)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $binary = hex2bin($data);
        $asnObject = ASNObject::fromBinary($binary);
        if (! $asnObject instanceof Sequence) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        if ($asnObject->count() < 2) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $version = $asnObject->getChildren()[0];
        if (! $version instanceof Integer && $version->getContent() !== '1') {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $privateKey = $asnObject->getChildren()[1];
        if (! $privateKey instanceof OctetString) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $privateKey = $privateKey->getContent();
        if (! is_string($privateKey)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $dBin = hex2bin($privateKey);
        if (! is_string($dBin)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $attributes = $asnObject->getChildren();
        $publicKeys = array_reduce($attributes, static function (array $carry, mixed $attribute): array {
            if (! $attribute instanceof ExplicitlyTaggedObject) {
                return $carry;
            }
            $attribute = $attribute->getContent();
            if (! is_array($attribute) || count($attribute) === 0) {
                return $carry;
            }
            $value = $attribute[0];
            if ($value instanceof BitString) {
                $carry[] = $value;
            }
            return $carry;
        }, []);

        if (count($publicKeys) !== 1) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $publicKey = $publicKeys[0];

        if (! $publicKey instanceof BitString) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $bits = $publicKey->getContent();
        if (! is_string($bits)) {
            throw new InvalidArgumentException('Unsupported key type');
        }
        $bits_length = mb_strlen($bits, '8bit');
        if (mb_strpos($bits, '04', 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Unsupported key type');
        }

        $xBin = hex2bin(mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit'));
        $yBin = hex2bin(mb_substr($bits, (int) (($bits_length - 2) / 2 + 2), ($bits_length - 2) / 2, '8bit'));
        if (! is_string($xBin) || ! is_string($yBin)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        return [
            'kty' => 'EC',
            'crv' => self::getCurve($oid),
            'x' => Base64UrlSafe::encodeUnpadded($xBin),
            'y' => Base64UrlSafe::encodeUnpadded($yBin),
            'd' => Base64UrlSafe::encodeUnpadded($dBin),
        ];
    }

    private static function loadPublicPEM(array $children): array
    {
        if (! $children[0] instanceof Sequence) {
            throw new InvalidArgumentException('Unsupported key type.');
        }

        $sub = $children[0]->getChildren();
        if (! $sub[0] instanceof ObjectIdentifier) {
            throw new InvalidArgumentException('Unsupported key type.');
        }
        if ($sub[0]->getContent() !== '1.2.840.10045.2.1') {
            throw new InvalidArgumentException('Unsupported key type.');
        }
        if (! $sub[1] instanceof ObjectIdentifier) {
            throw new InvalidArgumentException('Unsupported key type.');
        }
        if (! $children[1] instanceof BitString) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children[1]->getContent();
        if (! is_string($bits)) {
            throw new InvalidArgumentException('Unsupported key type');
        }
        $bits_length = mb_strlen($bits, '8bit');
        if (mb_strpos($bits, '04', 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Unsupported key type');
        }

        $values = [
            'kty' => 'EC',
        ];
        $oid = $sub[1]->getContent();
        if (! is_string($oid)) {
            throw new InvalidArgumentException('Unsupported key type');
        }
        $values['crv'] = self::getCurve($oid);

        $xBin = hex2bin(mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit'));
        $yBin = hex2bin(mb_substr($bits, (int) (($bits_length - 2) / 2 + 2), ($bits_length - 2) / 2, '8bit'));
        if (! is_string($xBin) || ! is_string($yBin)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $values['x'] = Base64UrlSafe::encodeUnpadded($xBin);
        $values['y'] = Base64UrlSafe::encodeUnpadded($yBin);

        return $values;
    }

    private static function getCurve(string $oid): string
    {
        $curves = self::getSupportedCurves();
        $curve = array_search($oid, $curves, true);
        if (! is_string($curve)) {
            throw new InvalidArgumentException('Unsupported OID.');
        }

        return $curve;
    }

    private static function getSupportedCurves(): array
    {
        return [
            'P-256' => '1.2.840.10045.3.1.7',
            'P-384' => '1.3.132.0.34',
            'P-521' => '1.3.132.0.35',
        ];
    }

    private static function verifyVersion(ASNObject $children): void
    {
        if (! $children instanceof Integer || $children->getContent() !== '1') {
            throw new InvalidArgumentException('Unable to load the key.');
        }
    }

    private static function getXAndY(ASNObject $children, string &$x, string &$y): void
    {
        if (! $children instanceof ExplicitlyTaggedObject || ! is_array($children->getContent())) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        if (! $children->getContent()[0] instanceof BitString) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children->getContent()[0]
            ->getContent();
        if (! is_string($bits)) {
            throw new InvalidArgumentException('Unsupported key type');
        }
        $bits_length = mb_strlen($bits, '8bit');

        if (mb_strpos($bits, '04', 0, '8bit') !== 0) {
            throw new InvalidArgumentException('Unsupported key type');
        }

        $x = mb_substr($bits, 2, (int) (($bits_length - 2) / 2), '8bit');
        $y = mb_substr($bits, (int) (($bits_length - 2) / 2 + 2), (int) (($bits_length - 2) / 2), '8bit');
    }

    private static function getD(ASNObject $children): string
    {
        if (! $children instanceof OctetString) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        $data = $children->getContent();
        if (! is_string($data)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        return $data;
    }

    private static function loadPrivatePEM(array $children): array
    {
        self::verifyVersion($children[0]);
        $x = '';
        $y = '';
        $d = self::getD($children[1]);
        self::getXAndY($children[3], $x, $y);

        if (! $children[2] instanceof ExplicitlyTaggedObject || ! is_array($children[2]->getContent())) {
            throw new InvalidArgumentException('Unable to load the key.');
        }
        if (! $children[2]->getContent()[0] instanceof ObjectIdentifier) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $curve = $children[2]->getContent()[0]->getContent();
        $dBin = hex2bin($d);
        $xBin = hex2bin((string) $x);
        $yBin = hex2bin((string) $y);
        if (! is_string($curve) || ! is_string($dBin) || ! is_string($xBin) || ! is_string($yBin)) {
            throw new InvalidArgumentException('Unable to load the key.');
        }

        $values = [
            'kty' => 'EC',
        ];
        $values['crv'] = self::getCurve($curve);
        $values['d'] = Base64UrlSafe::encodeUnpadded($dBin);
        $values['x'] = Base64UrlSafe::encodeUnpadded($xBin);
        $values['y'] = Base64UrlSafe::encodeUnpadded($yBin);

        return $values;
    }

    /**
     * @param ASNObject[] $children
     */
    private static function isPKCS8(array $children): bool
    {
        if (count($children) !== 3) {
            return false;
        }

        $classes = [
            0 => Integer::class,
            1 => Sequence::class,
            2 => OctetString::class,
        ];
        foreach ($classes as $k => $class) {
            if (! $children[$k] instanceof $class) {
                return false;
            }
        }

        return true;
    }

    private function loadJWK(array $jwk): void
    {
        $keys = [
            'kty' => 'The key parameter "kty" is missing.',
            'crv' => 'Curve parameter is missing',
            'x' => 'Point parameters are missing.',
            'y' => 'Point parameters are missing.',
        ];
        foreach ($keys as $k => $v) {
            if (! array_key_exists($k, $jwk)) {
                throw new InvalidArgumentException($v);
            }
        }

        if ($jwk['kty'] !== 'EC') {
            throw new InvalidArgumentException('JWK is not an Elliptic Curve key.');
        }
        $this->values = $jwk;
    }
}

<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyConverter;

use Base64Url\Base64Url;
use FG\ASN1\ASNObject;
use FG\ASN1\ExplicitlyTaggedObject;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;

/**
 * @internal
 */
class ECKey
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * ECKey constructor.
     */
    private function __construct(array $data)
    {
        $this->loadJWK($data);
    }

    /**
     * @return ECKey
     */
    public static function createFromPEM(string $pem): self
    {
        $data = self::loadPEM($pem);

        return new self($data);
    }

    /**
     * @throws \Exception
     */
    private static function loadPEM(string $data): array
    {
        $data = \base64_decode(\preg_replace('#-.*-|\r|\n#', '', $data), true);
        $asnObject = ASNObject::fromBinary($data);

        if (!$asnObject instanceof Sequence) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        $children = $asnObject->getChildren();
        if (self::isPKCS8($children)) {
            $children = self::loadPKCS8($children);
        }

        if (4 === \count($children)) {
            return self::loadPrivatePEM($children);
        }
        if (2 === \count($children)) {
            return self::loadPublicPEM($children);
        }

        throw new \Exception('Unable to load the key.');
    }

    /**
     * @param ASNObject[] $children
     */
    private static function loadPKCS8(array $children): array
    {
        $binary = \hex2bin($children[2]->getContent());
        $asnObject = ASNObject::fromBinary($binary);
        if (!$asnObject instanceof Sequence) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        return $asnObject->getChildren();
    }

    /**
     * @param ASNObject[] $children
     */
    private static function loadPublicPEM(array $children): array
    {
        if (!$children[0] instanceof Sequence) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }

        $sub = $children[0]->getChildren();
        if (!$sub[0] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if ('1.2.840.10045.2.1' !== $sub[0]->getContent()) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if (!$sub[1] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unsupported key type.');
        }
        if (!$children[1] instanceof BitString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children[1]->getContent();
        $bits_length = \mb_strlen($bits, '8bit');
        if ('04' !== \mb_substr($bits, 0, 2, '8bit')) {
            throw new \InvalidArgumentException('Unsupported key type');
        }

        $values = ['kty' => 'EC'];
        $values['crv'] = self::getCurve($sub[1]->getContent());
        $values['x'] = Base64Url::encode(\hex2bin(\mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit')));
        $values['y'] = Base64Url::encode(\hex2bin(\mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit')));

        return $values;
    }

    private static function getCurve(string $oid): string
    {
        $curves = self::getSupportedCurves();
        $curve = \array_search($oid, $curves, true);
        if (!\is_string($curve)) {
            throw new \InvalidArgumentException('Unsupported OID.');
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

    private static function verifyVersion(ASNObject $children)
    {
        if (!$children instanceof Integer || '1' !== $children->getContent()) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
    }

    private static function getXAndY(ASNObject $children, ?string &$x, ?string &$y)
    {
        if (!$children instanceof ExplicitlyTaggedObject || !\is_array($children->getContent())) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        if (!$children->getContent()[0] instanceof BitString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $bits = $children->getContent()[0]->getContent();
        $bits_length = \mb_strlen($bits, '8bit');

        if ('04' !== \mb_substr($bits, 0, 2, '8bit')) {
            throw new \InvalidArgumentException('Unsupported key type');
        }

        $x = \mb_substr($bits, 2, ($bits_length - 2) / 2, '8bit');
        $y = \mb_substr($bits, ($bits_length - 2) / 2 + 2, ($bits_length - 2) / 2, '8bit');
    }

    private static function getD(ASNObject $children): string
    {
        if (!$children instanceof OctetString) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        return $children->getContent();
    }

    private static function loadPrivatePEM(array $children): array
    {
        self::verifyVersion($children[0]);
        $x = null;
        $y = null;
        $d = self::getD($children[1]);
        self::getXAndY($children[3], $x, $y);

        if (!$children[2] instanceof ExplicitlyTaggedObject || !\is_array($children[2]->getContent())) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }
        if (!$children[2]->getContent()[0] instanceof ObjectIdentifier) {
            throw new \InvalidArgumentException('Unable to load the key.');
        }

        $curve = $children[2]->getContent()[0]->getContent();

        $values = ['kty' => 'EC'];
        $values['crv'] = self::getCurve($curve);
        $values['d'] = Base64Url::encode(\hex2bin($d));
        $values['x'] = Base64Url::encode(\hex2bin($x));
        $values['y'] = Base64Url::encode(\hex2bin($y));

        return $values;
    }

    /**
     * @param ASNObject[] $children
     */
    private static function isPKCS8(array $children): bool
    {
        if (3 !== \count($children)) {
            return false;
        }

        $classes = [0 => Integer::class, 1 => Sequence::class, 2 => OctetString::class];
        foreach ($classes as $k => $class) {
            if (!$children[$k] instanceof $class) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param ECKey $private
     *
     * @return ECKey
     */
    public static function toPublic(self $private): self
    {
        $data = $private->toArray();
        if (\array_key_exists('d', $data)) {
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

    private function loadJWK(array $jwk)
    {
        $keys = [
            'kty' => 'The key parameter "kty" is missing.',
            'crv' => 'Curve parameter is missing',
            'x' => 'Point parameters are missing.',
            'y' => 'Point parameters are missing.',
        ];
        foreach ($keys as $k => $v) {
            if (!\array_key_exists($k, $jwk)) {
                throw new \InvalidArgumentException($v);
            }
        }

        if ('EC' !== $jwk['kty']) {
            throw new \InvalidArgumentException('JWK is not an Elliptic Curve key.');
        }
        $this->values = $jwk;
    }
}

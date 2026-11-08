<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core\Util;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\BigInteger;
use Jose\Component\Core\Util\RSAKey;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The private key operation is blinded with a random factor: the result must not depend on that factor, and the
 * factor must reach the private exponent.
 *
 * The key is the RSA key of RFC 7516, appendix A.1. Its primes are listed with p > q, as JWKFactory produces them.
 *
 * @internal
 */
final class RSAKeyExponentiationTest extends TestCase
{
    private const MINIMAL_PRIVATE_KEY = [
        'kty' => 'RSA',
        'n' => 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        'e' => 'AQAB',
        'd' => 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
    ];

    private const CRT_PARAMETERS = [
        'p' => '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
        'q' => 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
        'dp' => 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
        'dq' => 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
        'qi' => 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY',
    ];

    #[Test]
    public function aPrivateKeyWithCrtParametersGivesTheTextbookResult(): void
    {
        $key = self::crtKey();

        foreach (self::inputs() as $c) {
            static::assertTrue(
                $c->modPow($key->getExponent(), $key->getModulus())
                    ->equals(RSAKey::exponentiate($key, $c))
            );
        }
    }

    #[Test]
    public function aPrivateKeyWithoutCrtParametersGivesTheTextbookResult(): void
    {
        $key = self::minimalKey();

        foreach (self::inputs() as $c) {
            static::assertTrue(
                $c->modPow($key->getExponent(), $key->getModulus())
                    ->equals(RSAKey::exponentiate($key, $c))
            );
        }
    }

    #[Test]
    public function thePrivateKeyOperationIsTheInverseOfThePublicOne(): void
    {
        $publicKey = RSAKey::toPublic(self::crtKey());

        foreach (self::inputs() as $m) {
            $c = RSAKey::exponentiate($publicKey, $m);
            static::assertTrue($c->equals($m->modPow($publicKey->getPublicExponent(), $publicKey->getModulus())));
            static::assertTrue($m->equals(RSAKey::exponentiate(self::crtKey(), $c)));
            static::assertTrue($m->equals(RSAKey::exponentiate(self::minimalKey(), $c)));
        }
    }

    #[Test]
    public function repeatedPrivateKeyOperationsOnTheSameInputAgree(): void
    {
        $key = self::crtKey();
        $c = BigInteger::random($key->getModulus()->subtract(BigInteger::createFromDecimal(1)));
        $expected = RSAKey::exponentiate($key, $c);

        for ($i = 0; $i < 10; ++$i) {
            static::assertTrue($expected->equals(RSAKey::exponentiate($key, $c)));
        }
    }

    /**
     * The public exponent is replaced by 65539 ("AQAD"), which does not match the private one. Then r^(e * d) no
     * longer cancels out with r^-1 and the result depends on the blinding factor r: two different results for the
     * same input show that a fresh random factor is applied to the input before the private exponent is. Without
     * blinding, the private exponent is applied to the input chosen by the sender, and every call returns c^d mod n.
     */
    #[Test]
    public function thePrivateExponentIsNeverAppliedToTheInputItself(): void
    {
        $keys = [
            'with CRT parameters' => RSAKey::createFromJWK(new JWK([
                ...self::MINIMAL_PRIVATE_KEY,
                ...self::CRT_PARAMETERS,
                'e' => 'AQAD',
            ])),
            'without CRT parameters' => RSAKey::createFromJWK(new JWK([
                ...self::MINIMAL_PRIVATE_KEY,
                'e' => 'AQAD',
            ])),
        ];
        $zero = BigInteger::createFromDecimal(0);

        foreach ($keys as $description => $key) {
            foreach (self::inputs() as $c) {
                if ($c->equals($zero)) {
                    continue;
                }
                $unblinded = $c->modPow($key->getExponent(), $key->getModulus());
                $first = RSAKey::exponentiate($key, $c);
                $second = RSAKey::exponentiate($key, $c);
                static::assertFalse(
                    $first->equals($unblinded) && $second->equals($unblinded),
                    'The private exponent is applied to the input itself, ' . $description . '.'
                );
                static::assertFalse($first->equals($second), 'The blinding factor is not fresh, ' . $description . '.');
            }
        }
    }

    private static function crtKey(): RSAKey
    {
        return RSAKey::createFromJWK(new JWK([...self::MINIMAL_PRIVATE_KEY, ...self::CRT_PARAMETERS]));
    }

    private static function minimalKey(): RSAKey
    {
        return RSAKey::createFromJWK(new JWK(self::MINIMAL_PRIVATE_KEY));
    }

    /**
     * The edge values, the values around both primes, where the CRT recombination of an unblinded operation changes
     * its course, and random values.
     *
     * @return BigInteger[]
     */
    private static function inputs(): array
    {
        $key = self::crtKey();
        $one = BigInteger::createFromDecimal(1);
        $n = $key->getModulus();
        [$p, $q] = $key->getPrimes();
        $inputs = [
            BigInteger::createFromDecimal(0),
            $one,
            BigInteger::createFromDecimal(2),
            $n->subtract($one),
            $p->subtract($one),
            $p,
            $p->add($one),
            $q->subtract($one),
            $q,
            $q->add($one),
        ];
        for ($i = 0; $i < 8; ++$i) {
            $inputs[] = BigInteger::random($n->subtract($one));
        }

        return $inputs;
    }
}

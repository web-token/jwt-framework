<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm\Tests;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use PHPUnit\Framework\TestCase;

/**
 * @see https://tools.ietf.org/html/rfc6979#appendix-A.2.5
 * @see https://tools.ietf.org/html/rfc6979#appendix-A.2.6
 * @see https://tools.ietf.org/html/rfc6979#appendix-A.2.7
 *
 * Note that we only test
 * * P-256 key with SHA-256
 * * P-384 key with SHA-384
 * * P-521 key with SHA-512
 *
 * Other curves or hash method combinaisons are not used by the Jot specification
 *
 * @group RFC6979
 *
 * @internal
 */
class ECDSAFromRFC6979Test extends TestCase
{
    /**
     * @param string $message
     * @param string $signature
     *
     * @dataProvider dataWithVectors
     *
     * @test
     */
    public function withVectors(SignatureAlgorithm $algorithm, $message, JWK $key, $signature): void
    {
        $is_valid = $algorithm->verify($key, $message, $signature);

        static::assertTrue($is_valid);
    }

    public function dataWithVectors(): array
    {
        return [
            [
                new ES256(),
                'sample',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'd' => Base64Url::encode($this->convertHexToBin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721')),
                    'x' => Base64Url::encode($this->convertHexToBin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6')),
                    'y' => Base64Url::encode($this->convertHexToBin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716'),
                    $this->convertHexToBin('F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8')
                ),
            ],
            [
                new ES256(),
                'test',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'd' => Base64Url::encode($this->convertHexToBin('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721')),
                    'x' => Base64Url::encode($this->convertHexToBin('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6')),
                    'y' => Base64Url::encode($this->convertHexToBin('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367'),
                    $this->convertHexToBin('019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083')
                ),
            ],
            [
                new ES384(),
                'sample',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-384',
                    'd' => Base64Url::encode($this->convertHexToBin('6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5')),
                    'x' => Base64Url::encode($this->convertHexToBin('EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13')),
                    'y' => Base64Url::encode($this->convertHexToBin('8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46'),
                    $this->convertHexToBin('99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8')
                ),
            ],
            [
                new ES384(),
                'test',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-384',
                    'd' => Base64Url::encode($this->convertHexToBin('6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5')),
                    'x' => Base64Url::encode($this->convertHexToBin('EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13')),
                    'y' => Base64Url::encode($this->convertHexToBin('8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB'),
                    $this->convertHexToBin('DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5')
                ),
            ],
            // A zero has been added at the beginning of each value from the RFC (cannot convert to binary of not an even length).
            [
                new ES512(),
                'sample',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-521',
                    'd' => Base64Url::encode($this->convertHexToBin('00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538')),
                    'x' => Base64Url::encode($this->convertHexToBin('01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4')),
                    'y' => Base64Url::encode($this->convertHexToBin('00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA'),
                    $this->convertHexToBin('00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A')
                ),
            ],
            [
                new ES512(),
                'test',
                new JWK([
                    'kty' => 'EC',
                    'crv' => 'P-521',
                    'd' => Base64Url::encode($this->convertHexToBin('00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538')),
                    'x' => Base64Url::encode($this->convertHexToBin('01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4')),
                    'y' => Base64Url::encode($this->convertHexToBin('00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5')),
                ]),
                sprintf(
                    '%s%s',
                    $this->convertHexToBin('013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D'),
                    $this->convertHexToBin('01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3')
                ),
            ],
        ];
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private function convertHexToBin($data)
    {
        return hex2bin($data);
    }
}

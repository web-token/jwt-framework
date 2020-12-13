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

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer as JweSerializer;
use Jose\Component\NestedToken\NestedTokenLoaderFactory;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer as JwsSerializer;
use PHPUnit\Framework\TestCase;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-6
 *
 * @group RFC7520
 * @group NestedToken
 *
 * @internal
 */
class NestingTokenUsingNestedTokenLoaderTest extends TestCase
{
    /**
     * @var JWSLoaderFactory
     */
    private $jwsLoaderFactory;

    /**
     * @var JWELoaderFactory
     */
    private $jweLoaderFactory;

    /**
     * @var NestedTokenLoaderFactory
     */
    private $nestedTokenLoaderFactory;

    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * @var JWEDecrypterFactory
     */
    private $jweDecrypterFactory;

    /**
     * @var null|JweSerializer\JWESerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    protected function setUp(): void
    {
        if (!class_exists(HeaderCheckerManagerFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-checker" is not installed.');
        }
        if (!class_exists(JWSLoader::class)) {
            static::markTestSkipped('The component "web-token/jwt-signature" is not installed.');
        }
    }

    /**
     * @test
     */
    public function decryption(): void
    {
        $payload = '{"iss":"hobbiton.example","exp":1300819380,"http://example.com/is_root":true}';

        $encryption_key = new JWK([
            'kty' => 'RSA',
            'kid' => 'samwise.gamgee@hobbiton.example',
            'use' => 'enc',
            'n' => 'wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE',
            'e' => 'AQAB',
            'alg' => 'RSA-OAEP',
            'd' => 'n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c9WsWgRzI-K8gE',
            'p' => '7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ',
            'q' => 'zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q',
            'dp' => '19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ',
            'dq' => 'S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ',
            'qi' => 'FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA',
        ]);
        $encryption_key_set = new JWKSet([$encryption_key]);

        $nestedTokenLoader = $this->getNestedTokenLoaderFactory()->create(
            ['jwe_compact', 'jwe_json_flattened', 'jwe_json_general'],
            ['RSA-OAEP'],
            ['A128GCM'],
            ['DEF'],
            [],
            ['jws_compact', 'jws_json_flattened', 'jws_json_general'],
            ['PS256'],
            []
        );

        $signature_key = new JWK([
            'kty' => 'RSA',
            'kid' => 'hobbiton.example',
            'use' => 'sig',
            'n' => 'kNrPIBDXMU6fcyv5i-QHQAQ-K8gsC3HJb7FYhYaw8hXbNJa-t8q0lDKwLZgQXYV-ffWxXJv5GGrlZE4GU52lfMEegTDzYTrRQ3tepgKFjMGg6Iy6fkl1ZNsx2gEonsnlShfzA9GJwRTmtKPbk1s-hwx1IU5AT-AIelNqBgcF2vE5W25_SGGBoaROVdUYxqETDggM1z5cKV4ZjDZ8-lh4oVB07bkac6LQdHpJUUySH_Er20DXx30Kyi97PciXKTS-QKXnmm8ivyRCmux22ZoPUind2BKC5OiG4MwALhaL2Z2k8CsRdfy-7dg7z41Rp6D0ZeEvtaUp4bX4aKraL4rTfw',
            'e' => 'AQAB',
            'd' => 'ZLe_TIxpE9-W_n2VBa-HWvuYPtjvxwVXClJFOpJsdea8g9RMx34qEOEtnoYc2un3CZ3LtJi-mju5RAT8YSc76YJds3ZVw0UiO8mMBeG6-iOnvgobobNx7K57-xjTJZU72EjOr9kB7z6ZKwDDq7HFyCDhUEcYcHFVc7iL_6TibVhAhOFONWlqlJgEgwVYd0rybNGKifdnpEbwyHoMwY6HM1qvnEFgP7iZ0YzHUT535x6jj4VKcdA7ZduFkhUauysySEW7mxZM6fj1vdjJIy9LD1fIz30Xv4ckoqhKF5GONU6tNmMmNgAD6gIViyEle1PrIxl1tBhCI14bRW-zrpHgAQ',
            'p' => 'yKWYoNIAqwMRQlgIBOdT1NIcbDNUUs2Rh-pBaxD_mIkweMt4Mg-0-B2iSYvMrs8horhonV7vxCQagcBAATGW-hAafUehWjxWSH-3KccRM8toL4e0q7M-idRDOBXSoe7Z2-CV2x_ZCY3RP8qp642R13WgXqGDIM4MbUkZSjcY9-c',
            'q' => 'uND4o15V30KDzf8vFJw589p1vlQVQ3NEilrinRUPHkkxaAzDzccGgrWMWpGxGFFnNL3w5CqPLeU76-5IVYQq0HwYVl0hVXQHr7sgaGu-483Ad3ENcL23FrOnF45m7_2ooAstJDe49MeLTTQKrSIBl_SKvqpYvfSPTczPcZkh9Kk',
            'dp' => 'jmTnEoq2qqa8ouaymjhJSCnsveUXnMQC2gAneQJRQkFqQu-zV2PKPKNbPvKVyiF5b2-L3tM3OW2d2iNDyRUWXlT7V5l0KwPTABSTOnTqAmYChGi8kXXdlhcrtSvXldBakC6saxwI_TzGGY2MVXzc2ZnCvCXHV4qjSxOrfP3pHFU',
            'dq' => 'R9FUvU88OVzEkTkXl3-5-WusE4DjHmndeZIlu3rifBdfLpq_P-iWPBbGaq9wzQ1c-J7SzCdJqkEJDv5yd2C7rnZ6kpzwBh_nmL8zscAk1qsunnt9CJGAYz7-sGWy1JGShFazfP52ThB4rlCJ0YuEaQMrIzpY77_oLAhpmDA0hLk',
            'qi' => 'S8tC7ZknW6hPITkjcwttQOPLVmRfwirRlFAViuDb8NW9CrV_7F2OqUZCqmzHTYAumwGFHI1WVRep7anleWaJjxC_1b3fq_al4qH3Pe-EKiHg6IMazuRtZLUROcThrExDbF5dYbsciDnfRUWLErZ4N1Be0bnxYuPqxwKd9QZwMo0',
        ]);
        $signature_key_set = new JWKSet([
            $signature_key,
        ]);

        $json_compact = 'eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ.a0JHRoITfpX4qRewImjlStn8m3CPxBV1ueYlVhjurCyrBg3I7YhCRYjphDOOS4E7rXbr2Fn6NyQq-A-gqT0FXqNjVOGrG-bi13mwy7RoYhjTkBEC6P7sMYMXXx4gzMedpiJHQVeyI-zkZV7A9matpgevAJWrXzOUysYGTtwoSN6gtUVtlLaivjvb21O0ul4YxSHV-ByK1kyeetRp_fuYJxHoKLQL9P424sKx2WGYb4zsBIPF4ssl_e5IR7nany-25_UmC2urosNkoFz9cQ82MypZP8gqbQJyPN-Fpp4Z-5o6yV64x6yzDUF_5JCIdl-Qv6H5dMVIY7q1eKpXcV1lWO_2FefEBqXxXvIjLeZivjNkzogCq3-IapSjVFnMjBxjpYLT8muaawo1yy1XXMuinIpNcOY3n4KKrXLrCcteX85m4IIHMZa38s1Hpr56fPPseMA-Jltmt-a9iEDtOzhtxz8AXy9tsCAZV2XBWNG8c3kJusAamBKOYwfk7JhLRDgOnJjlJLhn7TI4UxDp9dCmUXEN6z0v23W15qJIEXNJtqnblpymooeWAHCT4e_Owbim1g0AEpTHUdA2iiLNs9WTX_H_TXuPC8yDDhi1smxS_X_xpkIHkiIHWDOLx03BpqDTivpKkBYwqP2UZkcxqX2Fo_GnVrNwlK7Lgxw6FSQvDO0.GbX1i9kXz0sxXPmA.SZI4IvKHmwpazl_pJQXX3mHv1ANnOU4Wf9-utWYUcKrBNgCe2OFMf66cSJ8k2QkxaQD3_R60MGE9ofomwtky3GFxMeGRjtpMt9OAvVLsAXB0_UTCBGyBg3C2bWLXqZlfJAAoJRUPRk-BimYZY81zVBuIhc7HsQePCpu33SzMsFHjn4lP_idrJz_glZTNgKDt8zdnUPauKTKDNOH1DD4fuzvDYfDIAfqGPyL5sVRwbiXpXdGokEszM-9ChMPqW1QNhzuX_Zul3bvrJwr7nuGZs4cUScY3n8yE3AHCLurgls-A9mz1X38xEaulV18l4Fg9tLejdkAuQZjPbqeHQBJe4IwGD5Ee0dQ-Mtz4NnhkIWx-YKBb_Xo2zI3Q_1sYjKUuis7yWW-HTr_vqvFt0bj7WJf2vzB0TZ3dvsoGaTvPH2dyWwumUrlx4gmPUzBdwTO6ubfYSDUEEz5py0d_OtWeUSYcCYBKD-aM7tXg26qJo21gYjLfhn9zy-W19sOCZGuzgFjPhawXHpvnj_t-0_ES96kogjJLxS1IMU9Y5XmnwZMyNc9EIwnogsCg-hVuvzyP0sIruktmI94_SL1xgMl7o03phcTMxtlMizR88NKU1WkBsiXMCjy1Noue7MD-ShDp5dmM.KnIKEhN8U-3C9s4gtSpjSw';
        $json_flattened = '{"encrypted_key": "a0JHRoITfpX4qRewImjlStn8m3CPxBV1ueYlVhjurCyrBg3I7YhCRYjphDOOS4E7rXbr2Fn6NyQq-A-gqT0FXqNjVOGrG-bi13mwy7RoYhjTkBEC6P7sMYMXXx4gzMedpiJHQVeyI-zkZV7A9matpgevAJWrXzOUysYGTtwoSN6gtUVtlLaivjvb21O0ul4YxSHV-ByK1kyeetRp_fuYJxHoKLQL9P424sKx2WGYb4zsBIPF4ssl_e5IR7nany-25_UmC2urosNkoFz9cQ82MypZP8gqbQJyPN-Fpp4Z-5o6yV64x6yzDUF_5JCIdl-Qv6H5dMVIY7q1eKpXcV1lWO_2FefEBqXxXvIjLeZivjNkzogCq3-IapSjVFnMjBxjpYLT8muaawo1yy1XXMuinIpNcOY3n4KKrXLrCcteX85m4IIHMZa38s1Hpr56fPPseMA-Jltmt-a9iEDtOzhtxz8AXy9tsCAZV2XBWNG8c3kJusAamBKOYwfk7JhLRDgOnJjlJLhn7TI4UxDp9dCmUXEN6z0v23W15qJIEXNJtqnblpymooeWAHCT4e_Owbim1g0AEpTHUdA2iiLNs9WTX_H_TXuPC8yDDhi1smxS_X_xpkIHkiIHWDOLx03BpqDTivpKkBYwqP2UZkcxqX2Fo_GnVrNwlK7Lgxw6FSQvDO0","protected": "eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ","iv": "GbX1i9kXz0sxXPmA","ciphertext": "SZI4IvKHmwpazl_pJQXX3mHv1ANnOU4Wf9-utWYUcKrBNgCe2OFMf66cSJ8k2QkxaQD3_R60MGE9ofomwtky3GFxMeGRjtpMt9OAvVLsAXB0_UTCBGyBg3C2bWLXqZlfJAAoJRUPRk-BimYZY81zVBuIhc7HsQePCpu33SzMsFHjn4lP_idrJz_glZTNgKDt8zdnUPauKTKDNOH1DD4fuzvDYfDIAfqGPyL5sVRwbiXpXdGokEszM-9ChMPqW1QNhzuX_Zul3bvrJwr7nuGZs4cUScY3n8yE3AHCLurgls-A9mz1X38xEaulV18l4Fg9tLejdkAuQZjPbqeHQBJe4IwGD5Ee0dQ-Mtz4NnhkIWx-YKBb_Xo2zI3Q_1sYjKUuis7yWW-HTr_vqvFt0bj7WJf2vzB0TZ3dvsoGaTvPH2dyWwumUrlx4gmPUzBdwTO6ubfYSDUEEz5py0d_OtWeUSYcCYBKD-aM7tXg26qJo21gYjLfhn9zy-W19sOCZGuzgFjPhawXHpvnj_t-0_ES96kogjJLxS1IMU9Y5XmnwZMyNc9EIwnogsCg-hVuvzyP0sIruktmI94_SL1xgMl7o03phcTMxtlMizR88NKU1WkBsiXMCjy1Noue7MD-ShDp5dmM","tag": "KnIKEhN8U-3C9s4gtSpjSw"}';
        $json_general = '{"recipients": [{"encrypted_key": "a0JHRoITfpX4qRewImjlStn8m3CPxBV1ueYlVhjurCyrBg3I7YhCRYjphDOOS4E7rXbr2Fn6NyQq-A-gqT0FXqNjVOGrG-bi13mwy7RoYhjTkBEC6P7sMYMXXx4gzMedpiJHQVeyI-zkZV7A9matpgevAJWrXzOUysYGTtwoSN6gtUVtlLaivjvb21O0ul4YxSHV-ByK1kyeetRp_fuYJxHoKLQL9P424sKx2WGYb4zsBIPF4ssl_e5IR7nany-25_UmC2urosNkoFz9cQ82MypZP8gqbQJyPN-Fpp4Z-5o6yV64x6yzDUF_5JCIdl-Qv6H5dMVIY7q1eKpXcV1lWO_2FefEBqXxXvIjLeZivjNkzogCq3-IapSjVFnMjBxjpYLT8muaawo1yy1XXMuinIpNcOY3n4KKrXLrCcteX85m4IIHMZa38s1Hpr56fPPseMA-Jltmt-a9iEDtOzhtxz8AXy9tsCAZV2XBWNG8c3kJusAamBKOYwfk7JhLRDgOnJjlJLhn7TI4UxDp9dCmUXEN6z0v23W15qJIEXNJtqnblpymooeWAHCT4e_Owbim1g0AEpTHUdA2iiLNs9WTX_H_TXuPC8yDDhi1smxS_X_xpkIHkiIHWDOLx03BpqDTivpKkBYwqP2UZkcxqX2Fo_GnVrNwlK7Lgxw6FSQvDO0"}],"protected": "eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ","iv": "GbX1i9kXz0sxXPmA","ciphertext": "SZI4IvKHmwpazl_pJQXX3mHv1ANnOU4Wf9-utWYUcKrBNgCe2OFMf66cSJ8k2QkxaQD3_R60MGE9ofomwtky3GFxMeGRjtpMt9OAvVLsAXB0_UTCBGyBg3C2bWLXqZlfJAAoJRUPRk-BimYZY81zVBuIhc7HsQePCpu33SzMsFHjn4lP_idrJz_glZTNgKDt8zdnUPauKTKDNOH1DD4fuzvDYfDIAfqGPyL5sVRwbiXpXdGokEszM-9ChMPqW1QNhzuX_Zul3bvrJwr7nuGZs4cUScY3n8yE3AHCLurgls-A9mz1X38xEaulV18l4Fg9tLejdkAuQZjPbqeHQBJe4IwGD5Ee0dQ-Mtz4NnhkIWx-YKBb_Xo2zI3Q_1sYjKUuis7yWW-HTr_vqvFt0bj7WJf2vzB0TZ3dvsoGaTvPH2dyWwumUrlx4gmPUzBdwTO6ubfYSDUEEz5py0d_OtWeUSYcCYBKD-aM7tXg26qJo21gYjLfhn9zy-W19sOCZGuzgFjPhawXHpvnj_t-0_ES96kogjJLxS1IMU9Y5XmnwZMyNc9EIwnogsCg-hVuvzyP0sIruktmI94_SL1xgMl7o03phcTMxtlMizR88NKU1WkBsiXMCjy1Noue7MD-ShDp5dmM","tag": "KnIKEhN8U-3C9s4gtSpjSw"}';

        $loaded_compact_json = $nestedTokenLoader->load($json_compact, $encryption_key_set, $signature_key_set, $json_compact_signature);
        static::assertEquals($payload, $loaded_compact_json->getPayload());
        static::assertEquals(0, $json_compact_signature);

        $loaded_flattened_json = $nestedTokenLoader->load($json_flattened, $encryption_key_set, $signature_key_set, $json_flattened_signature);
        static::assertEquals($payload, $loaded_flattened_json->getPayload());
        static::assertEquals(0, $json_flattened_signature);

        $loaded_json = $nestedTokenLoader->load($json_general, $encryption_key_set, $signature_key_set, $json_general_signature);
        static::assertEquals($payload, $loaded_json->getPayload());
        static::assertEquals(0, $json_general_signature);
    }

    protected function getJWSLoaderFactory(): JWSLoaderFactory
    {
        if (null === $this->jwsLoaderFactory) {
            $this->jwsLoaderFactory = new JWSLoaderFactory(
                $this->getJWSSerializerManagerFactory(),
                $this->getJWSVerifierFactory(),
                $this->getHeaderCheckerManagerFactory()
            );
        }

        return $this->jwsLoaderFactory;
    }

    protected function getJWELoaderFactory(): JWELoaderFactory
    {
        if (null === $this->jweLoaderFactory) {
            $this->jweLoaderFactory = new JWELoaderFactory(
                $this->getJWESerializerManagerFactory(),
                $this->getJWEDecrypterFactory(),
                $this->getHeaderCheckerManagerFactory()
            );
        }

        return $this->jweLoaderFactory;
    }

    private function getNestedTokenLoaderFactory(): NestedTokenLoaderFactory
    {
        if (null === $this->nestedTokenLoaderFactory) {
            $this->nestedTokenLoaderFactory = new NestedTokenLoaderFactory(
                $this->getJWELoaderFactory(),
                $this->getJWSLoaderFactory()
            );
        }

        return $this->nestedTokenLoaderFactory;
    }

    private function getHeaderCheckerManagerFactory(): HeaderCheckerManagerFactory
    {
        $headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWETokenSupport());
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWSTokenSupport());

        return $headerCheckerManagerFactory;
    }

    private function getJWSSerializerManagerFactory(): JwsSerializer\JWSSerializerManagerFactory
    {
        $jwsSerializerManagerFactory = new JwsSerializer\JWSSerializerManagerFactory();
        $jwsSerializerManagerFactory->add(new JwsSerializer\CompactSerializer());
        $jwsSerializerManagerFactory->add(new JwsSerializer\JSONFlattenedSerializer());
        $jwsSerializerManagerFactory->add(new JwsSerializer\JSONGeneralSerializer());

        return $jwsSerializerManagerFactory;
    }

    private function getJWSVerifierFactory(): JWSVerifierFactory
    {
        return new JWSVerifierFactory(
            $this->getAlgorithmManagerFactory()
        );
    }

    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('A128GCM', new A128GCM());
            $this->algorithmManagerFactory->add('RSA-OAEP', new RSAOAEP());
            $this->algorithmManagerFactory->add('PS256', new PS256());
        }

        return $this->algorithmManagerFactory;
    }

    private function getCompressionMethodManagerFactory(): CompressionMethodManagerFactory
    {
        if (null === $this->compressionMethodManagerFactory) {
            $this->compressionMethodManagerFactory = new CompressionMethodManagerFactory();
            $this->compressionMethodManagerFactory->add('DEF', new Compression\Deflate());
        }

        return $this->compressionMethodManagerFactory;
    }

    private function getJWEDecrypterFactory(): JWEDecrypterFactory
    {
        if (null === $this->jweDecrypterFactory) {
            $this->jweDecrypterFactory = new JWEDecrypterFactory(
                $this->getAlgorithmManagerFactory(),
                $this->getCompressionMethodManagerFactory()
            );
        }

        return $this->jweDecrypterFactory;
    }

    private function getJWESerializerManagerFactory(): JweSerializer\JWESerializerManagerFactory
    {
        if (null === $this->jwsSerializerManagerFactory) {
            $this->jwsSerializerManagerFactory = new JweSerializer\JWESerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new JweSerializer\CompactSerializer());
            $this->jwsSerializerManagerFactory->add(new JweSerializer\JSONFlattenedSerializer());
            $this->jwsSerializerManagerFactory->add(new JweSerializer\JSONGeneralSerializer());
        }

        return $this->jwsSerializerManagerFactory;
    }
}

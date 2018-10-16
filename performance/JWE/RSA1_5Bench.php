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

namespace Jose\Performance\JWE;

/**
 * @Revs(1024)
 * @Groups({"JWE", "RSAEnc", "RSA1_5"})
 */
final class RSA1_5Bench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'RSA1_5', 'enc' => 'A256GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
        ];
    }

    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }

    public function dataInputs(): array
    {
        return [
            ['input' => '{"ciphertext":"2z1-hUCmtdU1It5AmfiJ-3VAc5OHuF7_8fMID9U6viZOTo7prG-OHoAulMYXAuEAh_y295NRSz093E_MO2geP2D9V3goFk6mhiVgGgwVnHk6eD-CM3oQjw_n9FzNRAsVuJkrFY8dFALFfUJOghhHpnPGwAuPCsHWJzCPQ9-N9lT2YQJZKnmrsclVERw_8ITywsfPfgGU0mb8Sh24m2TtUA8RDBtVmiHfAN1aJa0OC_w","iv":"6N4gVau8qYbK3w1JA8Ntwg","tag":"dnijlOO44TBcn-fpPKbchg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"N4aLO3KjTxM3odA-CWd2pxb-EG_LHzvbSkP0hXVlQh9mvP7bQt3FdKgnQUGd6_8P2IxEgYakZi7WemhkYKlxluSEyzymNMQ1RhOPuXcZAx04FVB3uGr5Jw7ig2HrCgG9HoX2Vp_CAb1baCicn4HA9vtH7O7SfUYpBUyyEbBLdYo"}'],
            ['input' => '{"ciphertext":"npQhGahpoW-x0M2zo-SMwREnoioINehE62pSP3z6AU0wQpYoDCa51r0RDjrrO290a3x0HoxCzlNUSnZJ_zhYePCTgIv7YJI0LXXcdZ0ImeoSg3OFxUJVuBBHE_tH8Xv4ttDziKUDGlQUeNtfahMtMa80ThTxnWL1jMrEwTWioBsgrAh3orLbNazdKKEzQqyE3hqdoj2BTfe5Vu18lSCUK4EZvYRTM3gUPKFJhmcYRJ4","iv":"tbj0JpNlArzfEDwjStBzfg","tag":"640hn-iRtO6tK_lLpzTB-lxKLm-xCaGk","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"hAcykh0bUdqlIrJB4RP5AiWjxeTH749gHY3giajV5NYpZa2lEXnscF5fjJWB4wXJfFI5gwoSPgoQ2ZeIjjxFqNMe3ionaG_gMmyfLcP7g43uMo9ppNeg0oHhq7LDg55AfSHsJXbMbx_3IfR8EKqpSEBd9a_NqnZX9_Zie16jQZ8"}'],
            ['input' => '{"ciphertext":"AmzqGzmRbyfdN4nti5YFtFQc-rpDJTn_rzfkfOxq-Y36b2QMXW6LJbzNfkY7niDI5YpgfELi4cwqJ0eagtoNstYpyOCBCmzKKzWAH6_6Qek2yrKwjEVwEst6OeeC97lg0OuYkcgBwDz-txmdz6lEeBj0X9yJiU6V5Gj8OHjYEl_FqmDRnypeBvYIuuiVAisut4xIeZvOZRN9sn15wuWnD1AGRTZDxCtpiaryaJeOeR4","iv":"EfKTRiKxAU0FRyfyAcMmnQ","tag":"mKWAfC9J8bZ4CMxrQkUH1NKJIkXgAKHQKtPqPZoJPxk","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"oH_69gE8MbmPG61PxU99j1mbwht9aEpXg9-PWp92eHQw8A_q-eVaZ1N_LEUxzmXZ71HvH_kigMqhl7k5GzGpqCR0eka80FuUtCvcfOBtd-MIcW4OfFGyQb71sRE-N7fbqXkQdTVtSqK4ZfjLUbGDTRewkK2YqwjWiK8_20p6ANw"}'],
            ['input' => '{"ciphertext":"Jyq1XGPri1anp3kXia0ElK12k6A7B7SNfLJ94g6W1DCXGPZQ-tgf6Ha7l2rezAHDjv9I595sWmTJd7eb-pum_bi2gbfMPCxX3j_7-jNRHZLVWzMZLe_5YH5Tp8I69IRQ-2fbgtGfhe77t2JugkWI03IamdjvvArSErV1neAp7g1W1WQ1SZ6p81ZODbIVlJ6kA9WRFcb9tHmzrK6DOogsyTcFbbnqJ-M","iv":"XxSTUZuJ4Izr_xMK","tag":"3HDxqZ1CdfTYi5umzknang","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"KcPwU6CsXF5kHxWHAuRl-z6qXlPfEv_HxNAp0IlbzBW4Ohk5YTd4QNHJgKhmRlRThC76HOwMLRmFjhq0ZUppvLtId0Ff1ZOxitcdxc52exyKex5tz05WlHIuTVESSoDv_65G4czpb8H3fvyRb4JA1raCfX12g5YwRK-v9wv3laM"}'],
            ['input' => '{"ciphertext":"6thPEeJm29Lb7M0v2-e6PKk-ztLYEfICpgwq5kQUgsHscr7pVqxHixMylukiQMuJ14s1TSm7a0s6qaQafz1S39D8jzqSFVJ0100rxGjmQTtlHvF1zO5v-itpVjPdVfMoC6VmZCmntsibPR2GQ61GczX7_TFCGeFwZ5pY7_-oxFZe7JZNj8nbWAKRn8gWXsQKsxQ9l_keA4qg_79UATbPCvJj6D-d8CA","iv":"bsiniVmwmyyWEyN0","tag":"wdrd1r7j8Jxh61YWMMSjFw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"WmC4orIjl4wB0czXIDvE-75NAoq0XlYkDcEczuWhMFNK7sXWUta7rV4-KV8z2DZ94TePx_GXEi-WUQFhl5Py0NcnCioRza31nN368NCv4-i0BFU6RdOw_pR3u8TddZMe-HjgRoUZmNcQR-2_Xg-ccBiHqaZecTN39o_FaGeqibE"}'],
            ['input' => '{"ciphertext":"VkrQfQR6Qwm7HiTIeWnVkb4KAfueOKfi4_6bthBwE0kyB1eGntSzTq_4ciFeqdlgsVvNAt4uwD_i8Ji4sOT5Nf8B5EKpDCTr7DdjyRlEzA1_bijS9LO3pwDL2T7zkIjfl_pnNtMGwAflxmTNIVobFLJdhBAVxrj1wOWod8a2aa_lpo_hyiKadng1937s7Wboz0wMlcTeUzUDCJvI57luXBLuLM0cmsI","iv":"yb1EBwSncsmKa5Km","tag":"EJKqSYbBoLxrb533aLrJHw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"SYecg8HD-cFZ-7Dv7zzBDGxa0GUrdv2GEEwcI91cqhTix-hzWDINWkV5RFbAs2KUZFxP05C4OnQKZt-NlqnOPsyoOVnNVfRGa6AGScVZOeEoTjW2ZK-zQ-AiNR-DbHHtqU5vO9j7-ChkyyWpszFdxIJ8FQaYS_RQLBMrPajUAmQ"}'],
            ['input' => '{"ciphertext":"WR5oOrLE1p_D5aZeSxvXBL1YI-uzzdDPBrgiCR7Fqm8Oabc17Ak-BsnW579zozTDklDrF-761n0k1BQD4rD7pKfLqa7yCfi8iqNyiIso6WZs9nKcSKYzzIUWnmBJwSdIBZvU7qE38df13GfROWgJPx85zmnIak5GouGBeGGpMi0grCXNvz9Wi9_mbrLSJtg2DaQx7EnsvQ6KlWmHyD1yPyaePaaMhgb8GdxbuPC-cUo","iv":"fBQznXDr10w5YTRrzViD1g","tag":"Qu3XUZJAvLkEZF_1LnqRJg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"sHIFzjVKcLzGYcVv-wD0pac0i86qHLfvLniA0HNjlhk5i3__sWy2fmb4pGc6QB2CNd57RZqezGJEsD6hbO3gHfVJAQ_9z-iaDcjuaYEWaMxdD238wAzZxoWWQQPNYEH1shMNqRaKCvSno4cUG3by-LSbMiB9lknYZMME2reMDQf_yh8AeoajdebxeDnoiivBJw6Z16SyJ9bSbofo9Oam2tFTHfP3xcP7jilWGoYN-weJYkI3RaeXmYkLlMpqWA9BFDJ6e4ZRyR8luOZCfSeRYx7a8dSzm3k-CvY3xXpLSIw3yeBsrrmt5i9mL3MJEcas0kGqouQxdx_LIRFK3qif7A"}'],
            ['input' => '{"ciphertext":"Nd_fAzWH92ozXLG0GOCzgeSz65AKftSKxo6crDcJpxYmHS9imQAVogivsDsQaV6yAs4d6wAq35PuT3iXrpNTKN4iXVb3jhBuXwnhz0T8BBCPApfQSHSCvCKc56is4Xk-wZm5ICXt-HYOpUJReAmGNm8JWj_6Pd7b09As9eM9P8oMgmR0Yl42zOXRo9Fcx6SeKKh9CazPmEq-r7aWv3SKJwYCt2U-JasX9Gg6nIrgIoA","iv":"kzQpYng7knFio-iXvNK8OQ","tag":"PVvTtB9RzaQXi7BXekHwdUvNiDtNX_zG","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"NS4ER8RlpoWHd2LnHGLFyx470zQoVesruOc2UQ1eGkCQek45vfjH55vipDNPrOfoEMh_nhNs80xbAZRnDbi01gCESyC7TQXXV94o2pnxNFG-g54fAWZuUr_L9-kQ7GcoCKcl5teLAoOEQevnjcM0RiL8Oo46KNTN7kYL7lXgFuwE-RqxtkcboasYRkxG4qu6MqkKWYsZiFlJ2qxgprXWusF_pc0XrKU_HVh8DU90TyUgIb0PWf25JneX3vK30aUqbmmsQ6S4BBj_ntZyD04fj7O7B2ztYZ_EEayA-c2CzK9PvgN21uuiApAvmNp6TN4d7DIAX3VEeWhgUG-nNwwtkA"}'],
            ['input' => '{"ciphertext":"Vo_R3-bg5v6dvuqNuiNEtLX0RqAEfzyTFAXtH342i8yk6JrP2kJSWmvkxxozQklCk-B6geb14mWkf8AviF0WVwvztV6W1WAMQhlEbOhIDUgkiti9jTHOvzE3n3RUlQa1-KZAeIRaF2k_pa7VpjNDciURSrvYz3cuOvKZcjYhYp1ktmbg_CvPo1dcSXuCRDDMlMDjD6lTaxk6iJZwmF6J34DIX8yiF8L7-cz7O1mRxcs","iv":"kH2RiycpQv1R_nKmeNyBmg","tag":"j89wsmugLXDE_EASPMGEMuubBs81PjkJ5A_4Bl-gooY","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"NMklVXQS_cVm2AlyoPoHnFOG1ZV3SBiTQQWq8X8q3uo9lIqWA1xZM5649tgGP3FNi7lqUq5Pe5gSQLrVJmXffPnXxpG_8SBURgXo884YeJxX68KPDb66sfAeBl32saWE7aBC9dXu7HHvWC5Gd9cXa6jjaMRdbkanBdytJH4ybZHfsDvtGep9LkdocdBCLprVDExfhYkXJot10JOHllesqbDAGvZ6acEz1DtnZHKTqSWllC25akHij9aTw-hjIklYjiZKLuA1-fIKuhy_QIYL73GQPKhyHQr5JolaVKkjf4Vb0SvLJeC9uxRNk1Ssww4PR-3IrEMyU7O5iDnMgpqKhQ"}'],
            ['input' => '{"ciphertext":"n-MtShwALqIo00cfsiOv8nFqKf2gP9qSxU3bU7RiaTbqNb2DT3Wwe2kR8SY0mGiqJvIv4grznWWgD4XH_WqeFbC7R9lD9kvhP55og2y1IWKtgqKXf8GGtBXW0IJ0uAkhCh78JoACXvgOMMvOkZ5BX9D4pulpn9c1TfsqirtVSZ20bSB9B1ynQQAc9cpVu9OAsqyxSK7G5HLXvmRxmIdW_Ctm1Xr4Vmc","iv":"B---hsTxog0fgWHi","tag":"5NOeOh81BKNlBO1HNCChVQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"J5JGsWDSZcPIqbuGauo23hIK2Q3Q8jAPvy5xxkwjRNu_joOsgtGlJoBZkDfh2YycEPMli5wFOR6QCU4fN9Io7dW0m5Q4fS89fIpaWNmV8u80MD3hjT0ErlVOe07U5h7ry7QiG_zx74lITsUI-2f13cpN1U9QeHhNc71yke8Io5B3ExlbMwxa2cvnoUMBrMFEQy54PIadFbt2SGaN--LTfN2WH2WbVcl7cgcQ_b77EO5KHHb2WtTxi30yH7yO-9fUnANeeP5_Mlz-rBSMXCBS0Vk0HhqmCt6SRLh2IygVH9xkyhsi6kozADcJY1T6sDX01vFAOkcAwsJDKdvREAyZjw"}'],
            ['input' => '{"ciphertext":"rxI3D-d0WKE7BlBek_0zsVv6lG-uwCjapLEpMobVeArbo0FWeXOQQunxkFGdH4_I_W_zMxrFu08Ms6hxOQnsmb2BtK6d6YfcA_yMOv05jS8yLLzpDQx5XP6Nmh2oeZsdgHwOxx9P163mnLmmu0mBfNRTCHDLLLYzMhzXaE_3ZKNaLlYgfbV53T7k8PHV0kXtdxj9NeWg6ScGA4i6UdmDmCQLRgfKlkM","iv":"tSSMtSp--qHBtaYO","tag":"AM5_KKNRoEqQX7kkWt60oQ","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"jHMCQc9sw5MFrU8mD3r44wV9vZqbT7eqARi4WKWJsPbbYtuWtbwgWbMajPmKyMFr472ZmwbBS96VXZH4Lj_rOROSRDe90Q_z4bnnnOIT80JB5v1anp-RJSwwsPzzCw_sSvZXk3Slo3c24eQEMNX6NyV8MP8Rk1iWDaV_zERhT-dM1-PrM-aZxvJPQDmmuTaRKZ4tExONQVclfVRbIeA3AVb-vRKgB9mLJCWWBnVVyhWiTkKet8cEXj7ZVgK80yejm_mBbdQ4KAPAJni1RZa2JWey3NqGZlOimMGeDpUENsLW7ef__z6NMQnLb5vwEayhdr4OFlp59eAI5mLEZRDqpQ"}'],
            ['input' => '{"ciphertext":"H1JXUesUD0F3lhxcuQoRhXjmWDvewTFtGEQe5WKZkLi-kbNeXYjmj8qcbm7T9YCRNnhCtjAcefpWZCTeF26tDPunQA0kHHhYkpqZDCpRdzf-6Mxm1IXxscnp0g3om431WQXZmf7FIQEcF6YgYWF4t9twEBfTBBguRhgJCIFZA_7-phYVEG6R1AZ52HACezdoXZIw9FeuK7KNE9LwfBxvB2QWZnxzUms","iv":"id8bvQio2jy4_4xe","tag":"Bp_RLw0GgoXyCVbDjC7_xw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"UpKgao9FkRXKRvWXI6wR1SOkc9ubNW63mmX0JP5MvWx3AZnPKXtAEdM1uB83FTrr5_k9-TGIbvspKFnLDsokFXBG5ry3YwDbbJFcKXk5PWCpZsmwECsq6eG1Ewki7DgUOWjx65ZbDIsIavsLEFtm0J1WBkMBot_mNpVvj2Opx0KaNQqbm-pudplXDzFTqByGgWkw_V5wV8f_k3kmfSncm8Ky1cPKUZTC7_jsD_tFtAIIUewKG_DqK-k-01AZCXE4tmT2CDU8xGW_EFJfbXkHswLC4552xEJ4j0265BoD7mo7-SHaeZ08cWIeEppyOw5osNWrWRhPKPiYSOqRdHsh2g"}'],
            ['input' => '{"ciphertext":"G2aTfp1NVbsPZTMxx8HAXsHlrTnJbbZ_dE7hIJPgyQZeGMJXPA3cJwQ-rZN8B6LI23qRooA6lXHWZbxqLZSAUeamENgIfq8jDVFL6LxZPFnuGNT6XY69GF4aph5P4xusk4BHWDFHmQy1GaYlgKlZ2TYb1Hrfm4qWSR6GM2xpxW4RzwfDU0or1d9xsVP8VwCOzx2B9_LIkS1oa5uulzqn0HVcPn-eS1CGCvjhpHqS4EU","iv":"EGXdp5njMEo-JmSKBfjvXQ","tag":"s0qjKqKE7l0TL8oa-hVeKA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"QILFkz0sewJZAFcuKe2hVvO7uuc6kBRiNOcBzhmjKAcs-wSJn5UzFYmeLcWBb658F9YRmN6Xzhe-rtbZJOFlgce8za6V9V71h1h2SgAOGjohflAoacq-a04rcEqhBV3cnH2rMoxcP-OEMYNVa989A8agKq7noYYzRpW6bKLkkddqaQ5XNrRSRPKDWtAMftPEKApdikg1TG5xf-o651sZznZFuvMTN1uMt1A85IPZiDveW8c2sMjGdk7yQnkK8ODhcYsHNNFERsSv3gaae0X_xy8rgu51jZwPocjLaSAK70mTegsJxnk4FAbuYMkfC3ZWm5VXjZTKFhC70A0rbY6sXMTjdBh3uAJXpC7gmg_oKPFse1q3L__KlPJy5vtMFZVT4JN4h9dmOZ4ZPw7X__c8Qat0wbjf7MeFPxfXs0q2ZZ_vPenAHiPqjR26FIj446BeKkg96-NHfqSZmM5aPZCQ6bRO0ODP-uizs3-xGR9k2aCqJmj4nzfGK76fIPMFGKxQxDSq81d_WdKP0Q-0pH4FIyqEf9n8PUzx6yrflEztc4RqnBVy1OAgzF2DsX3WO9ET279WTyFTGAOtF5kpdBduCsKy-YFDyOUQnl1cXYo2iUyGIVqX0K-KwUDACjg_SwAdAT6sc0guW4r_XrSBHPsWXibTgCh8kdDtldUDHOVFcWY"}'],
            ['input' => '{"ciphertext":"4P7OnC2zu2tz-kYla3rYjm0BUMaueWOrXSzyuRVwDCg39EPeV8HKMb1IKOtaIg4NVPe7M9KqbF3o3WSj7kcR0IhzMnZATucFJ-8PNkZL4rW5hB0zHTYI-Nw0fcfGzwVN_By5wyG_WQvA5Kw6rSJKnJX8LGohLv6EXQMYal7oiwsOtBw349Pc2vOJ0t6pCjGukwoymkj4l9z2D68UfwCTltfRsG3bQWWwcRtgo8L29Mc","iv":"ln7DkIIZo-pWQ4rKMnkP9w","tag":"6zmLsf0ncVJlpoRZS5Wr-1Rff1rKZD35","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"eXzUvKkJ8a29pNxfK8Q6MJdJV5txMeozw65mz1vNHMopDh-t4tPp36AUAI-EgQ-FI5cB78Eun477tetx-wKcrvkfQr_axYnE5XxWa3F-5pRJ8N7zLpCg5JievqCetBAPHqIdNSD6aFZFPu7vvpGVufoINmpI4lP_OfrWzU5fpe-K3JMkHee05Zdb0dXRsCJleaVr4WgMKvgUPLi_Fyr1vwjCKjM64WocC_Uw1h-GodvgqVI5douR3Hi5cGikUwkOUNhC3e6MhlOyScemnYsFFSVT107X-v7OjGzQvomXEAaczqR7BlgS5dHtSMoPRfsqyw2uPUXE7prZlLfIGSbyQfs7Se_aV4nstWdCmzPWR5uQ7FsSIuB70vv26jr1FoLdzURxZ-gigddet9wnjloGGsCWRYtsxh7SKpaQj1XYZ_M-lsSCWFJFKyA4xFS1SynukYHeZxwTqL_OSnmuBfoMMbuAcRly3j9saTKDtJnU7cgWe1AqIeFFqwAeQH_KWx8W2YSPJInrpAq33MluNVyJXpOFb3P_phF28pejKWJNf5GKWgEmpjQ4k16c7OlO-XOi421UV14Xy9NmIb6uMeVUcPaZzYgMcSVN0ZSeJ8I33p_OaT62rwROO7vRvm9fxuXSgeDhMvjU8pOJQGpaO_2ZGLIAa5GaW7WmnnLyaMBMUdo"}'],
            ['input' => '{"ciphertext":"4IBUPfHY19C7v-safTibYSvY_QIYBsi2rfOczWDW-Zn56yL20Iayc3oP8a0gY2e0PSAn9QvOHXhnSRwvfcXggWDBlpM7MCwK6lhhbqYf08vYFibKmB0oy_AAXe8_ysGBwHhPGTFE-uEXnDN4Oa4Q4jCMQ0XNHPDhy7niMrYiz9L26ibF2weGwRue9xpmd-zlNpZ1M8vj96i5VOC1WusJi_cBpfaXQDmCTCB8lhRJnRM","iv":"iDu5jNbgx1uSlv6-nJalzA","tag":"gnOPNV-nqL3qhg-Sn_17IZAyg0fOwr9NAr2ixaly01w","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"scfdJnEBkAX8ZB6rrkzo7urgG6K8ZS2uDqt7R_3MMu8vme-J-sFzrbgMr7oBunAZFECjagB5H7UJuZLQHH23zpcA2F1Xc-YCnIzZuCHCha-elf7u8r4Nev94J_Re3V0DvKpxVhtUVEtMev7WcJ-zCOw2h7Px3qqrvpm58N2prYtPFQuUnC8nbUCCcpxre9nrs3-BzwWTrM70DPO88W-Um4xj1rqeql8ySSCPhtBIS5MWGbKPnb__DT_0_cykKbki_Q73sC5rDMIie3ukGrbzjeUx0ylbt_5ELp9qh4mxP1wz8GwMluASF_XqrTnQQBsAOP13YfeSiNp9QO0xo4FSoGEAfkrXwZG7cCkzVjdg3Zdd9tx4uSGiVkC7-gu5HcChtXuQlfO5PQTW4QbcAP3nXIvZ3bXmU5eeorOp3OPY5NZTVb5A6ypO91glV8vgQZ6pLovmFslWICrZPFktBmKVZJeJqMjlv1ECaItzQSP_qlop5UENupcoRVEyS9ucKOKUEtk8q8eRBtM3EyKC6dlJPxuSp-XCp0fTuQ1jVcIFPrbVnfpbkXAnczxgA0JIgtkil3v_NDsUjEJjR_zH2HJXrRd6cxs7j_EA7En7eNExXdcAVJhWG_yP1Ub9JFv0WQ0op6AoZ0oytq67D6VPvwNgS-A_YxoWhVbgXS8__gvsvN4"}'],
            ['input' => '{"ciphertext":"ghUJEwroY_2vst0dkO6Idl8dqhPe6MqMhUmiI3enCxmJIasCSuVbYzy21UMdq0G-2cTveMtn-G8pUzkHKDbrzOFOwsXVzt9ZHag0doc27-INPv4WYkwsikGQL3PnIOzACJHOXafmxyIOI-HQxBR5gvFaK8hQs2rtIQsvmNAlP0BIm6EFBhcrGTc0uOQC2ldPcB0gEEQpTodKKAJ9DyUZcmWYeCr9lvU","iv":"GjgjMuEtJ6HNuJez","tag":"2Khni7fwgCNqJQUB0taMMA","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"RfZBDKkFbqRTRm6cI8SIdO_plSKynL_odIP9wuGH9oBjQDkKzyABUKkzCWnVE_hIKgvWzd4ppqmhGog268dBVpwaZXF7berRkwKTdCmIxPydzVcIKUUSx4ib2M3sURj0d169IWkLX4KfQwdaaSkP9T8dpntUDoBW7qgj2zEqLqkI2TDlwDSg5q1PfLb_lxe8nKh4sM_BKoCmrCvyyOzS0gPRjkufj2or6NhUEqHslF2zuzLQjEd_0K2ZxRh4_juNkslIN2Mxh6VM4U7UNoHv3lniudPpG3fM3O9UFkLT50Z_Q5aIWYXIUpk1C8U4CTBPIhZjYEFg_QOrRUb9YazhP31JXMFD3ulrXEz0Q5wuvUbiTf0ijL-K9wDz8AZLg8QGs2fEX9ZVD_9XPfzDOlAzowXGGIBeapz1CWGqF4xnvE3U5knXnNA58VmKfremy-oZInEwMvUBthXnnCKfwsf5tXlXRdHr9kQGDXLU6Q0yjnP-trJzv4JgGpQbB6_IT0KunW2qDYhX6zv3BunxqkNNZTJjhgOdMX6Z22lUVPD1H0Cd9_doftnzKuTa_fl6nDRwXLRWMOlXdTLO3AOhO72nBrhMt-PBwwX9Bpg08nThEPjpD7M5E_iHI9zEf0JM9iDwy3Gph6AKiokNswcQruN_i5eTB37xZ7IeMZA0vQKymU0"}'],
            ['input' => '{"ciphertext":"UWxD_tNuJpzQKQslAxWc03d_bB1b5POoImizYv--FQVFuShL-sjeWdm9L8FU87o6P43arC8WoZwrcdJvzfgVVAfuyt6cRvn33RcqhkhjhnLYl30VwaGmXn9LHdYlnVYtzzvaRooMIqX7HXsFarPVRBbGqokHGxCbKYz7ZxUaimbhhZwzkwPXZi1MjuyLgYqlKafpWaaxcLopor_Q_2pBz4OFO3LFHQ8","iv":"k2q1H8i_galIGE79","tag":"sur6mou_q_lXOsZoFz9ylw","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"bBh3zO9DlvATiGKbRghq7GnUQJGMQ_vmmcE7gfmysxzHLh-TX42Zwi6JlMZZPnMtPTlkv9EnOLadl0bignpJeWL8ZyE1FwNQ3U0FOnwFA9BLESac7jlX-KExMiAoznZ8_4RIasdAjM0M6v5ED28fBKRWW9co-WAE2Ch90z_Hq-Kr2aNAaYsm3CWcZYErCSp27GCs7FPVWwIo-lGQmesizh6nYhuy3f4ib9T_Utj-vhshW-Vl7xCjqLCI4beI1jiZjRYeHl4bxIKXSVajHoCxa7-w6-xFtzKXto1GWl0lgp9jSLu3gF2wqZ2ZBEvTgCo_LzJjwFEdmVFpKkseHsi0st1DomdDEduLy2ZuL4fbeQuvAA_iTNJZILIAyoTOrmrKXCCyHZsomiw6j_QnSXu07t5clViDUxGqenZplGKPUu_6b-2aim2AEUa8_aZlpzd8xA1zmpP08oM3SaoQtH_1B_VbQoFKHDIBIGMuHiHLoGHE7vZWzPjxEw54kPXGznrRjDdibSAy3egDOMFFJxbIsAYoelgm9S8K5pO-Zi6KiDWKbXYmGmhmlBqYBtEYixbYumvcdyJ-FpwM_hKmG1DfXpqhiH07g6ko8glhIcBr4GgZ3OGugt8NWd3aiykxL1e25rg-4A6FoQMQ6ixp4-8apTapivINP1REPngACEwvAMA"}'],
            ['input' => '{"ciphertext":"ImrQwhrkhCHsDqElXFAxDOcSwwv9J4I8Vn-RwYh3BuHEDX2935j-EmASf514il8mM-3KgrIhdE0_etiiSA9st5YfWlxEqAhsFf5FgGZlcyj4_rat3MMapcpfQYYf2a_dQvwQSj7tOrDAtFomYNQMuwbocLpaeQM_Qr8uoRu58fQHBZNF--dgum7gqvTm9Wd6Sdwl88sZeNhuGiU09SAP3NB2U2N-Q_Y","iv":"ZnVjlvwRIAggr5HV","tag":"grHDy7knCmF9itDDm7R9xg","aad":"QSxCLEMsRA","protected":"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"UPrNyHeO_gw9FmDrzy2nVVKxQj27zmYGiAPBB8pW-I1LbK4RSDKuocjW3ITvwKRA1WnWe3auVMh6M9_yQy7GPejXuS8lCthK3BNdP5Kv3doqQKFyfYdBZ_SS6RZ8NcXoz4FWj5iNF8pbsPCcWeWxDt1J1mPNiHhgRVUBXgqIKKyVBcOoP5ZhrJ9vJXI87PwiEt-awUrg456wI_ai9I3e-8i7hB-C_moauHNeTckMClevlfkNSnTigUNgcripbEDW1hq21ULuy2_xdf8eM_dJsiFaw6uBLJGhG2cEq2Aj0CHGP6c-HHXyBi4PYdGSXICG-RbePTcog05xXL38M7k_s62gQAG4obJJnCo8b0ZNbcUjZrfa8mxnNubFyvj6hSbJ-LaOpSLgH5FPRZcmsopuUvhCAVP-Rb3qm2m7vOrB4vxD9S8zqvfUKql8Rqxq8oPVxhpMXvlPIrOOMkLbVdddcUON_BdA520FlWgCPOXzvLpSXAydOqdy0YZju1P5u8nmHe5wLGnDGpCa7E3OTRyz874TfsHtVY-PytkXttWGS4MF5m_08Vc6NP3DLIBHaUm4UUwDSsagm6kiK3Cq2pIRbrAHGIWRpbimu6vlABNShTU2SyT5caRSVVUBaXmI49SHy7Lmg6BLp_z74p2zHCcP6i_1l6tXVgaUNeDf3D2YWxE"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'kty' => 'RSA',
                    'n' => 'p_Gffumd-Rj-hrWEKMZdfOw0JZci3dfVCkLYYISt60ajg8aktRR6Rc_1m_NMPIP2_BK5kXwWb74lqLh-x0iunfpgxHWnw4Wy00V2YwR0MtgbRW4JYyJjw9Fj7QooWdqRV7OoJb3VIpmBqr-JKjTV-91W6jPWcQNsUFYL5JsJ-sM',
                    'e' => 'AQAB',
                    'd' => 'pYj2sexpJj8pmfPOaTZkrZ5QJAEdf9aeiTer-S6uEqqUv22LqWSexLMfHvEn4rocNwfp2umZX9jnW69GXv1YBouBqrnN4vANPnjFp8y7ejKO_XDzKrf2c5YMgm7l4eE6aCHzEn2kFy971f97HN07KfiHNTln9boNGVsA6TpVrhk',
                    'p' => '2zIyk5fQMKC7vHqDCGQ-xEXRgiTZsQ2fN5gQ7rDsvGJdDBfpeWA8H3_bidSCNfAskSyhLoEFwQplARblm74BVQ',
                    'q' => 'xCRtcvPKTJ_uRZ2kxn8zMlETXcq1CBbuMLhZDl4QT6ksgAoOqnqITwckSXL2sTXTmDwgtuB1HYXk4TAXhwbrtw',
                    'dp' => 'EVJfMtCtcBpTm6pmznP1jdcinlFBLr-v1FndBK_QlXaEed8t4Rycw7R76eF0RMTtEK_hMOabSM0EfFiN3ofeXQ',
                    'dq' => 'rA5MWEcU0YyFhlnYHiucrGnEdEUJ8pOy09gSfvDym_6Jw7OO0-rywWhBY5DOZ_sQpv0vsVxKP-ChOwxlxxPCFw',
                    'qi' => 'FKqVgknFuntcWE0b4NSoqROngDbxLd-lQ2DWg9z7G-knJTizDwj_7tSlNbqYlcbXXNf5vRnhQCePb4KqKyPh8Q',
                ], [
                    'kty' => 'RSA',
                    'n' => 'slVGbcg7Mr_tQmfDJAIWrlWjBWpi_JzGTjCCVZGOikH3ekkUEH8TN39WJ2HXBwSNmT4bh8eRJsUyBKYr8yz3UdEUJxloo2SVZEN0rXh2Jb84OdObom1CFbPg4yQOvLN57pE06zc7GzQ1MKF2dqRFvyEyibKcs3V6J2DjvDXbxJAnTOmxWjLRKa6v9aKrNCakK_qSRzEwR-IbNnGHSrQr1RaDQ2gQ7FuVuNOJe8rrdlP1dIdg3ElzvDgjg3NY54b8SqwThXt8gRM1VKg5O-6fRdHLPS4L0DOElDlc8lboqA6oI1187cbLq__4P8c1pordIBmHXdbSd-4Q1BYnNVqfoQ',
                    'e' => 'AQAB',
                    'd' => 'rhaTB06lg5ha3C2BESC81XkiCIJfmWzOJbwzL6dFd_CHz6eRX709nDrBdvaLO_2U4VkA9R67sxZkCqfRVbW6xfMN8lFalc72C4fSWhmzdIvkLodFcl2oWplb20Dy5gFq8ZptB4XGPHtNxWiJxa39rGSS-lsToBj5o4FxL-V_4bSZOLWLfUIaFS5xJ4xZ6rLAH1gd8AlUbQfcwToDCjzyWSZDHFqCtOr10tD_3OeK_SdQoG4FGpnNo4WdUstTRTIYGaN8N_ThJh-f7bWUomEuBFhKT6FCXkxHbPfq1t3q9YhQBmg2_Jw9gUWD4lukPDpvdp-_blMRqs-9JNkL8plEsQ',
                    'p' => '53OBPF6RmswOMkuK8MhXjLT5NNCaFce9rKkpK-8KHK7UqVHqW006mzJ3kYVm2nIFODCqSO6RZcmEhLgrpZhAqbOl07lvh5nhhiXJyjaw6rcCumKTbjfX8dksnxHG2ik0Y8-1PHJwhIRHrjAeuf17XHgaATKOSxDVYSk-A7MClFU',
                    'q' => 'xT96R1C3y4zakgYWdThV9fn4sFgrlUFWrcMiis5dldl2k8aQrRCXRzWUNMK9G12ibBnXipVT24ZOQKJ0bqeoMU6aopY4DlsyWSzCEfJ6ojSE6Jd-Wnwb5TglNhXTq2wPjkpdbGTum7UeXYhdCJdwhc1GUkIU3ctTquY4isuyih0',
                    'dp' => 'f6oJbfgnzj-h0QI0KC4JhJZKI2SwqTTcnYFNMWuPo1SX_rEtWKEXo4VJyJ3RpspfsKe_Na1Jy-BE1UQU5yk8-Z4a6NcO-rfZWro7POu_2CeMPKyk75Wj6kXFRBR1H968hBWMvUPOZnnkY-Ms_6AezFl-1oxBSoyFditehoHV-WU',
                    'dq' => 'eoEtMaOpMwt9KFoNkqn1gXrKAMQR9XYKHotmJa17pDjWk3ssmcAHJJvbO1WDW76wxNDb9F9AIMRuT2hWRe9s34rBMZ94mzn6sDXDJqBhl-JkdYy5Vftk290eB1RRDVNk6eu30D1zkFNR06eAmHht0zwlo6sVCJdilG69yT4v2eU',
                    'qi' => '5vefHlL9JtiX-FBMYT6CSo51c-tonow5cj3Jl1crRuxod6zjXM13dr4bki40MT_ZQ8x1kjerFuoA1fYyktTAQnRgcafjYyZJIkh3RdGLf-_kDQ_up6v-k4IEile3RM_XST5lyq1ei6UuRO5NQDa5L9OctY5QWDz-rw9_51iKSUg',
                ], [
                    'kty' => 'RSA',
                    'n' => 'zBlgpPT7LeCKZbaRoX5iENY338bavaU-d_vw6xF4hYhqSBYoH2mt5WPeIW-lz9o1xlbxw-W6YnlHMuJfefnXOvZfFUNOK5-QGBq8ZJY7sfNJ0vxHJ2FJ8cNvpChTEqG7CRU6ZK_V2h5XuQFg4FGASbEgiJjRoPHrXwwts_e1ICIsW0Lg_YGBOk8RqlzguD-NcexYpO_N0VV-J5J5jlVxAEdVgddT-d9sGBx2Vq3PE3D8ZMTZ6UXTvmmdGK_CA-0Y7ep3UgYKVRmv2XLwwsmPWYJy8Ky9wqTnt58Lz5H6iZAGmgEztaf7hB-hRymDTFRWn2-zFhd1-TdqQ6xgZyfA4Qp7vFe1s9LZr_A-jFN2ZO7sP2x6e0dVDszzo0dJ41jrY4aP19hpOnPcXQ0sqjzahLmajekmtM3GjqBd9-bODXqCWiOhzc5Tl4Ru7_N1FEqUXVwBJhWelChez6DVTMeNdIJVw36ARtVNdsBwNTLK8q8n72cc_zwBmhFkGBdxHercMjmD1YJAaRfXfh8OJBbFJDSZkMp4N5PwK2iM4oy79xTsB61OZfEcwf1F4LKSDyyvJC5Mg1_Imc311nAdsDohBQMZquh-V73c6DhhBBRaAKk1esQoGUgLVBXsfR2RABr28WFM8RmOZKRdpI9AJO-6Z8X7a4JHCldljpyOX4mwWG8',
                    'e' => 'AQAB',
                    'd' => 'WS-lua-Lqyp5j6TN0oIFnFHfrJuarlBtEcU4K6BAyCkqOEHmWoO1h42yXW4KSN-TrA4GK5JRdgKFCEk_a2-vi4ZpWkNE_28EamQUeufjQgmL8vRmq2CqDUlXmaY9VuDxeDCcia8EhgHIV4GwsZUruAf8rXQJ9oiAT9JkjkXqEhacx2xcIKrcq3wtvgJD-H9c8bFTsw9PIvB25hftojLX5EVHqitL-N6Wv5qAY7Qjzt0KjYYvqu3mb0h7a3QyFcEfqadRaLhW_4TwANdnOdcWGwkT7POvIEUrNGP9p0Ck-EPFfrqTvAehssSXlx8eztXz3EvVOAwcc0Cx4MyMe8c1UtmKaXu7_v719irOXtECAtr7FfK_ycFA9dVQbKKBkj4MAidfgSLm5m9Ago8QnuyPHHktCcMzOeQNe6eY97rrBNpI3XEJJM97hnaIn1_g-poQgrnpYSZhTsDaKe9-ls8sD6RMqWHnVGe_bXsNfdi5G3iMqXAY94l0Eqrr_jTXdkmA-xTBCFfHcCLm5RDRBgc1zVYkl5d8rW822pyN4hfJsV1JR0KAltUQ2TCFR6fo0e6Ne-YbZDBHHPAD_s3m-2zSXSlODIG-bqR7beb8Ta9kjZo0advMbo4HjcY_qqd5KIY3HuyQWUGMABg96w_JxgFXEQVp3a6XQJaewQSRhsxTtGE',
                    'p' => '6l8TYYzb7VxrUFtKBbF1dTFjsRmAOajL6BGNB0Yyw0smZUEZL-HHeW3NzN4qB03oVUnNeAKKOde3-8mgDxi1qzB6ytqhJqrv0iRpsDJax7OP_F47um33nWcsipCHmzczM7f8HBmzD_beoMPGvsoUAzNIv9Ka0dz-1hQqz5etiKSMMwozAnUj_TqPLedc4DG6EaW8x_vgNfW-_puK-IzwsT5YjltQ8weufNxLlrT2sx9QT05jbxe2YR2ijNgvKxo-G0wz9A8pn5wiPB3NsdsHAy3mrtjMEjwv_Z65y0XPPO1W1Bp68XICknzghgTc7nZR_31NSrtEPmQBlJqoJPis-Q',
                    'q' => '3u8h8WiXSx6AtPGQpvmNebZqi66ITQcAhvdF8O_I1LdjswBTZwpXqKXb5kLBPXOAH6YqgxURNwZZ4M5Ys6iv66jVzPbSU_MMHlsiXzgeVfUxwbdOHpiZhRzoB2gzznfFDKR8bu1S07tYePeaEwplsSg2Vb5tC81uNIM1sshfeuDO5cZOH8DmuJzTjhGjb8CWmbgLnFOSBuPl-Vcr3oYVCnWzvEfCgUIy5tC9KeBC8Qe3O841SjbN3yZ8EEXwcUmo9lOt19s3LKBmtT94SXtok6-wHVWlL3YbzRg1kl8SVjN28NJd990mjPhjqBK8KyChCxoPn8lIXEUwGwFmIz4Spw',
                    'dp' => 'tYIqXVscnAf-KD565kvX_ongfjCUqJL8T97_zIlmGO8jbjlrSzTdKkKKpsXL4NpKO3srwGyfJkrVdw9ggTCOyWSDRITrVyn9D08Z9tYYjh6XPUixkyFFKkbULP_ftaqbYct0WULh9VQoeHMGgY24z_2wsrZlJnCzf5Ig0aLTR0bAOWsFtDqKQ7xNVKygthRs2Ov1dx-vNbr7Tu2hQ_rLEUmKhb1cxMrHLHXjqHS_tlti8_huc4P2v-GWmON4LDZnsPZkKfhwMOdXcB1Yxwwssx6iT_kgmmK4e_-oPi_zXmkk3KEhY8n7Cf3iWIh9ncROnsIo0N6U7IjA3Jil7fQU6Q',
                    'dq' => 'kYMy-5jST_Tr-69FRMfU4WIA74WPb_-nB3F1VIue4cGGMPuAdNxaVTlVbFmcOlkegwn566-fmfPqTINDgJkVotOEIhHlPWiCO3ou2EoP-vldbd0Q_4WJh0pT5SnNzvF8TAE9O0Zq7sr1N5geGFmMAPOHa7YtBSwkx9_w9-4z7Ee6pF4o9i76KfwrVisLK9FgO5vW8EXYJekxXevZNZj9OOOU2stYGPi1stUC88duylbH8iBpxjQ5cnNzPUf5Zmi3AXmjGib7P4S_JYT1JbmIjAV8Bdm2RWFpShiINy8ZD-ztsMkPDs9p70_d9IGuEtRsaYusMRa3xYpfmPDz0wMcNw',
                    'qi' => 'sEHok5K2HG0q6JdNzHB7FsM9EJxY7c6Gkya3Lfr1Rr5OYPcAosEIZpl-1_hCQ3MLGKT9UlYjZrlyt6SOUvCkxFX9slDZQeagmlSNMyWs18U0MxhFpEGthqLthS6ik0kFlschiSpMMyKVI8kgQR3OjMDcA_Mr92gZ9fl-mhtl2yfXJsBIkFBD7yOyxRxawy7v05RehoDHmdy2cnzaakPvg3Cekma2mfdjYgN5JnS0A20pC1zfoqi0D3B4KGrYVZhyJRnBakOUmwvE8rfmcjThx169LiAea6SYs7k9jwUCVWrNexXItxGdbQbbrb-FUotAcAQSDr6hHU8H79gN63WoOQ',
                ]]],
            ],
        ];
    }

    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'p_Gffumd-Rj-hrWEKMZdfOw0JZci3dfVCkLYYISt60ajg8aktRR6Rc_1m_NMPIP2_BK5kXwWb74lqLh-x0iunfpgxHWnw4Wy00V2YwR0MtgbRW4JYyJjw9Fj7QooWdqRV7OoJb3VIpmBqr-JKjTV-91W6jPWcQNsUFYL5JsJ-sM',
                    'e' => 'AQAB',
                ],
            ],
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'slVGbcg7Mr_tQmfDJAIWrlWjBWpi_JzGTjCCVZGOikH3ekkUEH8TN39WJ2HXBwSNmT4bh8eRJsUyBKYr8yz3UdEUJxloo2SVZEN0rXh2Jb84OdObom1CFbPg4yQOvLN57pE06zc7GzQ1MKF2dqRFvyEyibKcs3V6J2DjvDXbxJAnTOmxWjLRKa6v9aKrNCakK_qSRzEwR-IbNnGHSrQr1RaDQ2gQ7FuVuNOJe8rrdlP1dIdg3ElzvDgjg3NY54b8SqwThXt8gRM1VKg5O-6fRdHLPS4L0DOElDlc8lboqA6oI1187cbLq__4P8c1pordIBmHXdbSd-4Q1BYnNVqfoQ',
                    'e' => 'AQAB',
                ],
            ],
            [
                'recipient_key' => [
                    'kty' => 'RSA',
                    'n' => 'zBlgpPT7LeCKZbaRoX5iENY338bavaU-d_vw6xF4hYhqSBYoH2mt5WPeIW-lz9o1xlbxw-W6YnlHMuJfefnXOvZfFUNOK5-QGBq8ZJY7sfNJ0vxHJ2FJ8cNvpChTEqG7CRU6ZK_V2h5XuQFg4FGASbEgiJjRoPHrXwwts_e1ICIsW0Lg_YGBOk8RqlzguD-NcexYpO_N0VV-J5J5jlVxAEdVgddT-d9sGBx2Vq3PE3D8ZMTZ6UXTvmmdGK_CA-0Y7ep3UgYKVRmv2XLwwsmPWYJy8Ky9wqTnt58Lz5H6iZAGmgEztaf7hB-hRymDTFRWn2-zFhd1-TdqQ6xgZyfA4Qp7vFe1s9LZr_A-jFN2ZO7sP2x6e0dVDszzo0dJ41jrY4aP19hpOnPcXQ0sqjzahLmajekmtM3GjqBd9-bODXqCWiOhzc5Tl4Ru7_N1FEqUXVwBJhWelChez6DVTMeNdIJVw36ARtVNdsBwNTLK8q8n72cc_zwBmhFkGBdxHercMjmD1YJAaRfXfh8OJBbFJDSZkMp4N5PwK2iM4oy79xTsB61OZfEcwf1F4LKSDyyvJC5Mg1_Imc311nAdsDohBQMZquh-V73c6DhhBBRaAKk1esQoGUgLVBXsfR2RABr28WFM8RmOZKRdpI9AJO-6Z8X7a4JHCldljpyOX4mwWG8',
                    'e' => 'AQAB',
                ],
            ],
        ];
    }
}

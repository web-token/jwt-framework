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
 * @Revs(256)
 * @Groups({"JWE", "ECDHES", "ECDHESKW", "ECDHESA256KW"})
 */
final class ECDHESA256KWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"_2ZDM1eBLjU6k1XygQn5q8FcTZf9Bu_dlbjQ-MPh1jyQ14YplP2r1iZSnVke-UbDTFUGj97RZw4ab5PRxaWdo--OEY9MBDK-PK4HaLuM8mgxM_VY2VNLROSuZZc2Rk0UYWr5JLAq9l3N-6Ayjbn4L1EAslENOArzG05EdNcUFzkYjEm4dk5lN0_1ueL-8sy4CN088iUBm2ypygiVt00dnWd3d0W3zwgZiH53GE7zzQs","iv":"11dtOFD32AesbnRi4DKTMA","tag":"naveS2vDGMoeTyV0_eEv9w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJmRDhiSXJkZEFkQUpSMEhsajV2eHdSSFl0eE44QU95c2loX2phcWtNLXFFIiwieSI6IjFZbmZmcGNiVzNWOXhmYU9mcWg0REZ1d1NFblhwaWdESnFvS2k0V25BejQifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"-lbBek3DTQlQm9LY7NoBdSdiLUsea94bCjEq__slnG1oAnO3OugDow"}'],
            ['input' => '{"ciphertext":"5IBzhh0acduGMoWjyRw0RTqI8byRTqE7jIR9So25ioKmYRRzHTUi2rIKvQzWY80u8wGe1hh7bX_nK5HyQztvyMZnECR2Z1xAWmZlNqEcV_QH6VUqfvnw0w6od2FMkraq7b-MFXTyVtUyqaW87OeDo1WTRrMOc64SfsVpQ5xLhhppC_LM3iTFOG7R-ldjyzWpoSqy6VkYGqTM5_EYnYiMfdPikr752uUnO97HiXQ3bcY","iv":"UJpFJkgRWQ2FDDHuHsizpg","tag":"ANvdf48Jr6ixFdCTgzj512kksNmKdV0L","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJxNjI2TTBFaG9jalRFVmNwSVZvNWduNmxuRWpOVXVIbHgzb05mU0pJTndFIiwieSI6IkFCOHZJR0RWWU5HNkhBSi1jMU91RjVUd0d0TkhVNUJqUzlKbUs1UVBCYVEifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"CTUn875mWqvFzSqrz3YEpIXscd6pgMurvMjESuFNUmjE3E_CBrdq6IngiJVByr-z20PczS-ovD4"}'],
            ['input' => '{"ciphertext":"2-ph7JTQllkn5k59nLjyCvPFmC9Wo2-t9ec671GNRJ21CGDoCcevjESNfP_3cXnPBRneKotf8h7Vz1oC0hcZeMPXVGZUD5LXmgMrsWrXGF0vFN910E3ToOnOPhduYe1dM61DoYzwrgoP0t13IFWG7KQU0SjLDgAkiC2QChTIhLk81G52u1DWshpQdc7UT9Lfv8RBPCkltsfu3NlT8fpB4JABXDIJbXv_1M2ybfqqg24","iv":"tc8wFvNZ2I-fcHNhFxJtzA","tag":"9iJNeBy0m2JkHfHSMFT9j1rGj_RwdjDB5X4VQssehvQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI0cWFsb0dBWUVHRFhQVThmWVQ4UzhtU3N0SUFXcUtHb1FKUlhkRVcwaW1ZIiwieSI6Im5lUGhqc1UzNlRGYV8tZFR6R1RlR1hZTjFnNmNIMTBkVk44WmpEcmZYU1EifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"zEVPN1GHM033Q7Ghz6uBSdgjC3CJZZOca89-iG8lIPdiIwI0OPoIOMWiPIGs_hwR_RMgdhnPa70MV4XtmMgo8FyyjOkwOsfF"}'],
            ['input' => '{"ciphertext":"2EZFKdOiXzI0ZXAd7F8eOM1csiDF5eJCKusj7jVGYEQgj3uJy4Tdm372CynBIop5jHQgCk_o4lGcJzQvnUC03x5ayR0u9g-6PYr7lvpPcJ5NSr1mfehN4whG4K33wGR9YY3FigDOZMWCSj3-qnTcw4mKvixnrhNd_lEYbcXp_foBH7L2kIs7YkoiLLr8__2va8aWBIY8vw7W6_44p4YjDU_i0JS2-GA","iv":"ZflD-9NFEjppvYSx","tag":"mcdC1NSqbjmD_imWCZxbYA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJDSFpiT0xQYXhReU9pMndpem8tUjh3QjAtRVFFTHhBQnJ6bS1TdVRHMFZnIiwieSI6IjFNOHZyVnRINVE0QnFjSWROUnVfNkctbVBWVDFqaEw2LWxkdHBDQzBSckUifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"ZFrUs0U01E3Sccm31VHeHAnzDaYMAO6i"}'],
            ['input' => '{"ciphertext":"3Hi4-hGfQ9CNzmkhKPg-uAAHiEzjxMz4jtSDmTuYkEo3-Ribc8H4M_Bqj0adpAS58mnPz9I-uEqrflUXeHAJ-d2Vb90gf1R8RKVjV-7Mqi5Bxhv98GFIZrHGFqmQuJ95yh8TdxSJXvMvKDkhe8u8rA2MgxNKbs63EVBr4GMCqRWGqagfOVHpkcobTdcDDpS6RKXwBfNyLVv4QdqyBUyjGAH-FgF2Ims","iv":"LV_MzlgZlIuEXYxQ","tag":"ui3S0bL6TSCgNaCSov7Vvg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ1NUhFLWRIV2FyU2NzdDRQQWlDZ1RKUVlnbWFCdDR6SE5aZkduV1NqTlIwIiwieSI6IllRQzAwUnpOWUNSWl8wNXdHelN5WmVwY2t0bTRaV3JQemtOdmtGbEExSEEifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"8dCnxob-1n2tC6HgfsLTFvc41WzriaHlV_qIbdjKY0g"}'],
            ['input' => '{"ciphertext":"pt41hd0_vaDa0O5HMf6E78OtCZlZ_r4-lwtUl48kZqqoz7k9tdmu_zrAIFA_wW7ieCp8-GBu9R_Ny2vH4FFvvQgMtSXx2h_YBAH8oPCDKBoiNRM2AFlC4T7palBNkFS-01y9eJkxwjmRgdJJYXWnCDSK6AyEsPEVZMOqVNK-fnp9-U3bUPBPSGFTH48Bs7NTB7hAMuLZWbMoJKQAQdz-wius40-nof4","iv":"dkYB6DStRMEOOT1v","tag":"XA304bY0KsYBu39T2IDjBA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJtVExiaF9LaFpKaGR0SWVXYXZENi16Nmg4blJjSHNrUWhXcU9VMUNiVWg4IiwieSI6Im53VnRYSmcwSU1WbFpXM2NYaU9ReXFmSGFvMFVXNXY0czNhOGtsT3BXV1EifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"C1B2p6_G8v2HuDH4ElWQzdCbaTepSxLNh9l_a3Nw-vTkwQgXtzDq9A"}'],
            ['input' => '{"ciphertext":"9qoT_yY1nVIwztNUHOfP6dtTfJQpvcrQ1uLAm8aFSZhSpIyg9xyJ_BVtAAyv7Grtfxt1f4N5YUK6M5zMf-ybhK-0ybudJHkLWoj0YtAvP1KkM3Wvq_GTCQ2ZdBjqIVKJTnUEfWmlGV6BXPVXLWM0X3svSJBCEwEOSQEufX_cI-mfcUi92VLN9rTTkDokvTLVntSGThcqydm8ZtmOg8u02liuHqEhXy0_gYFC_XY4Am0","iv":"abExYU1ldE0GO8_K-Wy4_A","tag":"uSMzfuP6WQzmTWn0OHa10Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJjSVlwT3RfVFR5X015UE96VjNJQ3gxd0prdGZZLTM3SWV2bmFVNnRtaWZJdG9qNWpkTkwxZmd0VkplMDRfXzJrIiwieSI6Ik1ZM1B6LTQzeUNjdlUzYmUwMExrMnBIel9IaTZQYl9RTWUxeXk4MWpvMDB6Qm5sUHFMdVg2d29uaGhGWTFnNE8ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"zw5MEB3t4bAJ8GIa7x0DGQzybmnhR_ADOb9kNZI2-F87hHLi1-LTPg"}'],
            ['input' => '{"ciphertext":"GKfqg-1I9ItJSCsiDY9yIhYxnGuskdxPy_rXbz9MYOtmDNnRWNez8DlVmPf0AWhJSkYvCIohhCmbtighJJNJq0wGbriU9MjZogtWTzrUUhzEkKaZqgg-ofHcF_eow9h3GsQ1TEdBk3bOFLVxqBkauOR4qw7KFi42l5MNjJs1zLRihJvB3FxqJ79Dbc-1KZBcMmdNyoWFlzDCQazaZBpgPz5OYmN60SzhWcIkfaWXwX8","iv":"7AsW-AFjgNJyxSeLNQ5WdA","tag":"_E3l8ER_XQmNeFGrZnaE5HB6cOFs2gQf","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJoUUVxMVNaX3dpQ3k0enlNeVRJU2k0WmpfSGhNVXk5ZWo2TVVWYUhvelUxV1JJNXZ0QjdWUGFGVHc2QmUxejhLIiwieSI6Ijh3S2dhbVpLWW9EQUsydVFCeXpMWnBCaTRUVGpfZE5XR0dXbzZTSVc4RkRIaExPSjY1M2RFZ3VmREREVFI2WFIifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"en1pp2tN0ZgevdS8KwYpbcnTgxyKKbIs1qsETtGEbXJ8dUz59q4dw5P5LNGgs3ITQkKyAHIy-po"}'],
            ['input' => '{"ciphertext":"Q-FDEcUo_6zIyfnH_NApjUH7V4A4eQ8XJ6BF8SHg7qP6a8gjweAdYtHmy7CxvWOcvRdmyLNvfz93muQvHihRMZKvM7Cyl0BLuqKlQkwVmln94PypmsoYxoopl97zcdCTpkFYNvL4PLBomAVaagX-q9Xs7LL6r1hi1kf_drgoivfVQxRGrOkVw7Hm6us3dWG57Wpe8wWAGmJAY_I97owJC8-8zczJTMDLTiIFmPIo2pU","iv":"9aC-2rcP3gIKjMe4M_iOtg","tag":"IPNDjw-b6cbTuNuj8DWWhJTFW38IQQQbjuq9ftxCVms","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJBRmVfajJ3WDBNaFJMbmMyUVBwMjZrR1FEOXBTUUtiYW16a0xYX2l2NEFKeGsyVU55cnkwd3NZZ2JMeTREQUdFIiwieSI6IlJ1YlhZM0tvaXM1UzVZeVhOczhLTER1aDhTQThwYV9ocm44ajdNc0t0OWdKRnFWcDhVaUFDcVJDR2VnNzNtcG0ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"43lvgJ17neOuzGkKKe-4FJi7YKkoXpfVNJsqdjBUzRD9FNkun8cmVuVS1TBt-PsQJIugykuhCv5tMihMzSODbZk8P46_4oG3"}'],
            ['input' => '{"ciphertext":"tqQ3LzEqIGZE94SoOskld4xuAmX3kguPPN26_Bj_MTrWEqUlbQ7D6dI1jcbXZZb-iOnIuto9CYb7uSniY4pR-klRH-9hrTX7dMGhZzuzY3hLn6JL-zlr5bZcbGl0Wsd5TZ8jxPJx6BMQ6ncCFCi4EhraSt2ty5Z3H5RaGXKhMOcER0vqfIxIQ7ij-yrJ_e11zRRxCxPgWjpNIkvvZzMC3XMMLgSHjls","iv":"kdmy4535OG2eGe5t","tag":"XwtRf4h8Bry_NAh2ReW-zg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJQQ1JXelloWDF2RTA0Sm9LNTlzQkN2UVloRWRKc0NhbWRTV1oxSlVhWGVHZWs4T1plNjJaNGdxVkRMMVF2aVAzIiwieSI6IndsVEZjMDJFdW5kUnFnTDBEbmFqcnFHYWMxbjEtNWx3TlgtOFVGWnZzQ2F0OFpyMFcxbWVvcDdzckRTdnliLXkifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"wRHEx-f-GthCfVhqjVJNF-h8PKLt8smF"}'],
            ['input' => '{"ciphertext":"_s0KJ5Wqqk2xsM4zlACqSX-VGZHsXhyGisdymCnGMuLh3oJnAX6hSDCVHCxNxduRXCF2WSsTAUfa1yLWs3GsN5ndbqLZZYDVHGSjtCSI4oBODo3Xp8NLpf676xjGJUem_VtqmiLLiV9etJieOB7kfZOa-DwGVc3RQkOabne_EmsornckgS0YXN2s61qOMCrZehPqP_Jj4JjzRIxuDKYVtyIN5rCGe4s","iv":"1XPPKja0ZDqv0o4G","tag":"bS5OAUL4-sK4Vo2bmMt7wQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJxTGVQUnVNNmtaTkZuUGhMMC01QktpOVBIZGJKdDJxZUM1REpiMXhlUTNWbThpNllwUmc4SFJqZVZPdmpJeWIwIiwieSI6InpiTlk3YnhtZ3FyZ1hxQ3IxdDNPVkZxdXgyY1lqRl85YUNOV1RvcDBXaV9HY0tNREJkLTVqZGNvZG1KcUhxZk0ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"cA5I7NM1g16i1K3fFNapEajLRWlTY8Xi7ICLD9iICPk"}'],
            ['input' => '{"ciphertext":"7bAhp0XwPvbnVoLW7CD51u86heDUrp2CpUKSQXtcouS-LtY6ytvf7rC7ZVfe_-t6apo1jUIGaswxTl-ma_xOxuG2oybLwhXirKnRRryDHQsPwyMMLPMt2t-cXSW9QCa21KtkY-mxTpn0JZusIrT7F2zzovJmIR-4jlBqd_YlTT_BsoB8TWgSBoUMeoeZ9RFW-uBSeqCWBWeNyZH1lzjefYALYJ333Ns","iv":"4RZE4V9VHKPDIvIP","tag":"zQ27iVw3u6CW9JHhKvTdsw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJvTmRQNV9LT2lEWG9sMWhFNmRaakxnZURIOU5kREJfQ3paWEtqWC1VWkRaLWQ4NmhxN3hGWUwyWHhac2Y3dll0IiwieSI6Il9pZGpKLThiUjhnSVl2cWdzZDU1QUJkTl9pSmluSURETXBBb25uMnRFRE5KZ2dOajgwYVgwN0hYS194SVlhZUcifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"O2qIqAxybaUIEAC3NKq450ptzk3pHJ33DOg0xfajJ9sv_w4_OfHrgg"}'],
            ['input' => '{"ciphertext":"cEE2ph6vE0gyDsCGsJZ_N6cRRxvJtuFiLIwLMHntzIDrAiJb3DR0ks1dtgjTpAm4hKmkgG4ftZQ8zDQRk9mDMCKabO-eXo-evzxerqKIQBV5EysgmKojXfiG1f5MH5wKK-UwPgcMmnodQ_AAZMflrXXo2PbXL8OQIyIMbm7Mdx1NxbDKhFP00qS2ad0fdhNRL1dB5yzLHDMNPenYL3A1sDyAWcItRj8u-mP6V9z3K5w","iv":"ol8jKetABAiwv2QDNEJLUg","tag":"GFZsZlXowylyG5OTrzhcvA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSGJlY2VBTEcxbVBXWmtuLWlqdjI1RkZFS0xnS1hqczVpMzgwRi1KdWZmd0lZYmx4ZklfanRCWnlBZnhBdFZFWDdkQWJqbGp1WFBPbFk0aTJGWFRfSmV3IiwieSI6IkFXc1Z2Q3d0Nk5SblBQMWlqTXNFd285RnlxbzFEV2dEeGlZbmdSLXZFTFIyQW1lVV82UWRwQlY4VUI4cnA2RndER1d4Mlc1aW93bkd5TmM0azJTeF8wcmEifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"RbuaR9R6aYWKqWBOFi517v8P5IjBjOmj9ev0T4EsNHuDACV4Zh_xoQ"}'],
            ['input' => '{"ciphertext":"tX2AOnAGCPECJc6w9zlsW_MAq9XC3JOQ6wg6zxDll3vmnRJ9j9CXkr56DMMFD-C1zmeiDgEIhcpMCPfkgJzdYz5hTygm-gK0EHNiwoNjHoNTMY1l-W2dy4J1ICxC_2ZRuZIs__ePHwcmvQE-JZhbxi087akNRIZ6A5Ujz8Y6MKdLODxL48Hr-qd1gyle-1QRodceu1deqmnLC62k0n_WNy7dyy9M0FUF-YHnHO_MLnY","iv":"vr_5AlQqrn4pS1T67DgzwQ","tag":"0tqhT1oHgUpKqWag0Rge49L4Ktrw2fA-","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVzZPTjFOVzNiaWFYMWlWTXA1dWJZRjJKc0VzRE5JWW82MFdkdVBVaHBwTWg5UUNpNkl2bWtSTWd3SWhtX29icUo5WmhkU2I1cWpsOTdUYmdrLUpqYnV4IiwieSI6IkFFR0VFSVlYMkJEZ2xCSlF0SC1idFlIRV8tbXBKUWRpdGFpVFhndkNXQWpRZEp3cnU4VVU3S0JvdC1od0pCWVBYMjlKUEdzOEE5TTlfUW1Za0diMEZzb2EifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"EM3zGRZ3IXp58aqF9-ISJVmYyDrp19fCd2UHpWD3HPukYsYgZHzqHo8v0vlVsYFvGlahiStIfKc"}'],
            ['input' => '{"ciphertext":"__hNdjyA4YeCtHlz1fNjcajEx4S32PjNs1uKdgXKmas5UbNNFpuY2ITR6bu31EGs4FTOokFfxkf0FanWbqLOT0FFqSbh0jB5y_gg32xLrXpNWUZrSHsb6Q8WaNfl5j-lWnKowrSPxPXATZhSBCgDFbRp1Y-nck77x7qdvk4u7qAxpUImvQ3bOWdoOjAyxxj6BU-uP-yNJgml3BzEya-qU-8nGTxnlTjyvaeLDDjXPX8","iv":"OOuRSCC7nvWaZaYXOcXnwA","tag":"Jl9rPZU04Do3bJMvHTS9DEuOlVkQ31Z9b39qWfxZvp0","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVXhfaUVwV1ZQUGk3Ui1Vbm02UlE1dEdRX3hqNWZIQUJXeldkMEdfVWdSOC1UeldvbDZRUXVBZW9mdVRxbm5KbHYyajZFTE9ScjI4Tnc2MVZ6UTcxdkFFIiwieSI6IkFFWG91RXB3bjBMcU5DcHJIYnpsby11WHRQazZWUXd0TkE2WTY1S05uZkhUVXpDWF9lVGVUY3pwTmRnY0dPaWE4RklRZ3A4OXRlUWw2Q1c2eVZFeFZiZWIifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"Q-hZp5Ts6maPrD7e5GhOfw8eMxEWlWmR256N7LH--4yIRVhfIcs7KGF0LfmiovdlLIGLPDPCI5UOBWj7V5lt4q4QNx_qHWqu"}'],
            ['input' => '{"ciphertext":"5eU_XuShpboU9NilrZWfcPlUMSN-VNw-aF9BMioU7aq-CllNT0y0l_JQYw8Z6L0QJN1Xd8zG6-EOVVlwZDTGgmfcl8xPdDbhmDqkZKIE__ejHs05wkE9d-VVDaPMBr6-qz9PMZh_rI-Io7jlbRL6b4E25okNlB4vfmv21hWP6-V4FDefqk-KI8-8uhcX3TXTTjvIm6XN9T9qjHxGC3V5AwqdM9vS2ns","iv":"kuM67zZvVGjHCp-l","tag":"FJxF24EhYJfRceXxPThaiw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBQ2QzWi1GNURGdXdvUWhRS21uR2R1M2Jza0paeG1yN2pWMVRHLXhFeXluWTV3bFM1REhVRU1FX3dtVkV4d0FEd09HMzdYZGx3ZUI2THZpR1JhWUR3VjZsIiwieSI6IkFYM1dGM25VYl9sZktfelhyYjQ4OEdtQmYzYlVSck5jZjdPc2RGSGlDMk5UYUVzZkd4aFhOdjNEdWxEcUdwUVBxMWtOSmVKb2l5N3NLcVpGWm5KeDM5SloifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"YcVE0diKwm0751TE9PnT-Y5SlowoRhg_"}'],
            ['input' => '{"ciphertext":"uei5DL8ETBiQkCrCBSHCrkpMKYGKf5pnG5DfY2LQO0rCub8t72uQy_9_M0mxN-2KymlIJ2xXzevaciv1AiJKKZ2dw_MqAotMKkbY3-CWoLcui3J621DTPdInRWa_yBfEaZjcAyROkMXGCCwSFstSi6NxJCoepw_-N4DEpHnNOdDp18AmSEZyiUVVEoWyVzGKNnNi1IZfpPiUPlGUoMhMqcdO5N9l0QY","iv":"9-6zjl-SYClhgSMH","tag":"vGghyBNPbX0b4WAZ_yGOLg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBV1oxSnlEbjBieVJfQ2VYUjRvak04Tkd4ekt3R0xsandNeDNuY0VzbG90eXM1eFVWZG1zQzd5V3NFSkVZdG5sNllJQ2lUdC1QeUZUTkp1NkdZb3FpNThjIiwieSI6IkFCR1g1NC1MNEhEc3FZSkY0dFpZMVFyUi1ndVhyajh6dVZmZnlUbXJBQU9QWDExdXk2R3g2YXdxNkVZMWRjb3l0SnkxN05ZZUxFZHlvdV9tMXlZTW1FWTYifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"zGy_4_TYMQrn9t-8oJCB4YngUFGj2jSpMnMTCosDLyQ"}'],
            ['input' => '{"ciphertext":"lzyAnuakQHLY86oQDPvNBov7rCZ14F8jCbsGhqAAakAi5I25s3qdIrUQkCL4gf8odOtsXYIDV7aQfgE8KFr9cU4dz57f76kuHoOxSpcoAS95nWdsUVyEIngmIxA2-zsP_9XlCvxR10MdcJMRc1rJBx7cl__DLcv5gPXQExETloHEBEgZsY1CX_RQ6KQhY36MPHVyWTg_UA-2hlJECg2y9drTMTaKp5w","iv":"eYdDBftinJCe944e","tag":"2UJDc2WZ0_cKQ3ARMxBM4A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUFVDYlhQeEVlbUllc1Q2UGNvUkM5VzZFMVcxaUMtc3VqdTBUQ0o0N3NZV19qMTdobHdidWhtRzBSSTdUdzZfQTRic3JFMXU5WEwwanBQMUN3RmNXRmRpIiwieSI6IkFRc3NfT05JaXZxMnhYeWg2YkZPYzE3b2U4RVNxV21Kb2VTZnk3Qy1tSDFUX1g3SEZ1eFVuSS0tbkF4ZkRlbVNfOVZhQmhXLVhDSjBJSU5BMXNmYVFvS2wifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"VESVX1LZuNBiAIbwRmkpVRcnJJl9pZW28nLqqLo9F2EWz6tMYa6t8g"}'],
            ['input' => '{"ciphertext":"8qZDYzB4oNkaZ9fuP7VbBq_tgav-f4GRlm1LqlfSjru8CjaJlazysmCyTmiLMnlzRK8SBsJJHl3cD6mzE9th3cUXNnZDv8zWDyGJG1cqSBN9l1eNjm211wApKYS0Br4VeYvmCe-UqicQ9oY9HSTGfvOmoS2muUOcjq_E3NoaMBy9aCfCxpI0zbLToU1Pi6XX0067COb2-bYdubqkvvWv8hp8PHjWaXvL43IHQnzhopo","iv":"YS-zbeYANkS6GEVpMpJIew","tag":"1DnLg_8Ih2ZCSFUplq12QA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkQtWGk1Wm10TWU0bDh1cVZfc3ZBUmdxa3NYRFFnMl9adGVncG5LbFYza0UifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"u9-hFbvn6zywUw5BXi-bq4xyGRSnfnZWwptY6M4yoO9LyKHsocB6Gw"}'],
            ['input' => '{"ciphertext":"Xuc77DY9PAIQ_yoVkKToDlhW9uk0Uzfaz9MciGY8eWGh9VrFcmuNG2H8gSsUStt-baNm-4VDeQMHslrsitzbr5J_oOidGO8W9zbkzPmBPTZC_5QjXnbXzjt9K7nV-Hj_gm1GCrvWWUhV_3wBqu_ImGvxBKwok7lbDuGzPl34emq9fuwgZm1hMsVB1ceG4GdT7gyWI-l3_ZWiPZ9PnohNiiEweOqXPIxM3SKlfZccUeA","iv":"B_4Jk2jT8k1gbL7kBA4UGw","tag":"014BQVWe_gTnHHO2KiTjvXTQkmjcQGDR","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkljUDBwQVdVX2xhdHRSZnFLYzg5NnRWdHN3b3FMVGdpbkR0Nmo2RGZyV0EifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"rLPSUu69AesWy5JDXfVWf_013-rTvXTJ4Oee6kGkGMU9dE8HvoH_i71r8DeSso8-U2jys27HL-o"}'],
            ['input' => '{"ciphertext":"3WxZ-AFPhFmAFyB-pVPIexSD4WE2oLLPkUx03a_-CQFauAssjHo0qVANrolX_orqi1mv_bpy9BHN448JkWPmR67ceGh9QA0wJFf7murMjMQDsc7tOcmUUx6_r8stuT7otp8HpDER9-p9tIIStAFcHmfOoS7e47Zim3dl7dp9aiN4KJIobVnlURd3ea5IgDxWRA_h6GEZsZR30X-DWkMgxzy3Ww6JB3t5RNOp4cLghlw","iv":"U5mvwDvMQo2jUg8KE9eUmw","tag":"R3AXFz5R1u7hsdo4hs-LdbNKSn-l3YkMr0itx8yRYKU","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlhUXzU5SVltd3FnM0dYX3NVZ0p3V2h2ZjRwVWxVNjk5YU9wS3BQRGV1dzAifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"YXkavPBVx5ofJMT-KFm_ejahySbtIl8zYgZYM7ldnE4RXRdd0uTyVrpe-IQPXiw1GwulX6Wru0_yx53KhhHm0dreUdNlDhKf"}'],
            ['input' => '{"ciphertext":"WAdVz48yPbEzv5v1V9HNMoF5VaBhPwz5vRseWAPZKTIyNqdA6umpTZ9qm96yWuqYb2yH0w5Cxe9dpR5YmLFPSqOs3Gps_kjJR-jOxwgQ8HcF7NM03H8RuBFHbDmUJnbmDTmsGL7zd2ETcTFojzZGw3mH-WGpb4DngVGVB7N9NtKLA7fo8DkO80pcjz0KXAPVQZ521NitqLf3XMwOoT3VPC-MAl4_6C4","iv":"LzUS-9qKaROPKhDT","tag":"CcYTnLTMuA5yy04akakr7Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6InRYeXp4QjR0M3h1aEQtdEd3MW9teVhCb2xpbVlWRFVBMXVUVDV0UlVxa2MifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"TmWcX0cXisnCFjD_cWaBYmkKkruAx9Vk"}'],
            ['input' => '{"ciphertext":"SXzp2Qqa5YD1JrO4OSkrCSDvPc2zggmY3cu1hbKm-gLCGPsaEyx1HB3M9mWGJRUV2puLfx9YgKqwSaEtVfb8K2eMh1DcX21UYGl6ZJnL6nYhWOQ-VXqXgMme8aQxoG0-pv_i_ktUcH0Q8Y9X-dO5NxHYR250-TC3K3DdvBXguqAZaNxXt6QZLAJR70NUS0ckmI1G0-_HgAQ9otf5kl5XuJCCiwTpTn4","iv":"LflxldeSJrkcI-sa","tag":"Qtb2B4ya3Y80Asrbt2ZPTg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Il90Mk9yamEwUWQ4Y250TndwTEJWemdlRmxJek9GbE12MmNnZTFUZ2NIU00ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"XVGVJ_M9SqL7mCdWsytLbhy9yVkjnBHwcnG0880GSx0"}'],
            ['input' => '{"ciphertext":"3RiKN4NFaGrmu9o4VJqqt1VfH6HtVhIyTkY5BPFOgGefdUrmLZ6i7pnz9CXwrajoroFyyISUqMe-qJqhZgnzE6n-WPnYRd6pyYRlqfqK5W63YtWWNCKvRI33Cyoro4EITxACqzU58hH7I9Q1UNETkT5UcrK3ICZKngsTafTfhAC-YitjnXc_AmRsycRK75bUiNJeutyaPBTwAFCqB_IA-4FlGwtV79U","iv":"1zrIIE5dPwAA7RcB","tag":"mlFjdaJAn5bB9Yvk71GvFw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ik05ZVpVQlQ5OWU3bHNmUlBCZGs4b0kxaW5ERjRPUzZhUHJpaDQ4dGlSVVkifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"jMlWsTieWwXF7Izuj0pa-g-bwJadXhV6EtFEcGZBbWIRcNgeO7tUNg"}'],
        ];
    }

    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'd' => '_gUgAjx9zU5BKlHq--TiCjZmsdNQAgrv536DCTUM2vo',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ], [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'd' => 'Fn_Le74znJfY33TkqCoskx1pkgA_1sLnKvfvM_78lTZT2zfj4XC6uY_L8iRknOii',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ], [
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'd' => 'ACebnk5N5RV4VFhrCmvp-5w6rsQJvHdvvBdJkIKmq3pDDreKC0vU-K2oYrQaX5vPuI1umnVw9qxFq6QCsShJ38Fh',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
                ], [
                    'crv' => 'X25519',
                    'kty' => 'OKP',
                    'x' => 'LD7PfRPxq03bd0WJyf_1z-LQevmrbcYx7jJafep3gmk',
                    'd' => 'pSdgXFRYMvOa7giAm3Rrf5Mf8GnvLz7HtZKu_KN06KY',
                ]]],
            ],
        ];
    }

    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'X25519',
                    'kty' => 'OKP',
                    'x' => 'LD7PfRPxq03bd0WJyf_1z-LQevmrbcYx7jJafep3gmk',
                ],
            ],
        ];
    }
}

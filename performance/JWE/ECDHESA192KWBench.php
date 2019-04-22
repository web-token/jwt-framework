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
 * @Groups({"JWE", "ECDHES", "ECDHESKW", "ECDHESA192KW"})
 */
final class ECDHESA192KWBench extends EncryptionBench
{
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A128CBC-HS256'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A192CBC-HS384'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A256CBC-HS512'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A128GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A192GCM'],
                'shared_header' => [],
                'recipient_header' => [],
            ],
            [
                'shared_protected_header' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A256GCM'],
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
            ['input' => '{"ciphertext":"239HNO--jJWqy20I6I9aQ5x86whqVQjFPlN9YRYjOi8ekbOM5YGIuyhbYF3Gdo2-MTqxjFZPOQ8VZVN8hdIL0n1hPIeD0IKl7Um1NcKShGtQtu2Sduyxa4hi6jAqf8LwvzjpVtI7o9DXE8HHUr1-XG4J4-mzDxSBFgbmIR3O0pWqp5-NdaGNOVkVlfbcTRimuDBsKZdJ6jWF6dM0SLq91rHC5mgtfPtYgvV38U8shvE","iv":"3iT5_YJ5uoslgv6uTlRgSw","tag":"Cxpt_nE_2RFs44A2G92Cow","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJpWVRydzFaaXZtdGh2TjVIYndGX3d4WkNoNVJmNFV0WTJjV04waVlVeHlvIiwieSI6ImRISlVpdDFkSVVFM0hjOS1OaUtHS1FNNnp1djBaY3Rwa045NDdxOWxFZkkifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"Gvg1uxRX6GpWKaLL6Bry2q454RfZR7psyruGv3kuf9kNPJD5-j0RWg"}'],
            ['input' => '{"ciphertext":"RDFW5wr_AqtcHGKv654vUBzFzHE9DQHExhS9r3uPxSDjI9NikzsjHEV8YjXVX9if06gzoHHb-cGXuJRoJI1gC9TY6kx77oll12fEu3FgXVuL1gZ7U9Ujj5wgI-scT5UmdxgUravP9Qim0kwTmTqXAn0RRuI2jVIZUhshzHUhuj-QsPDR4wrccMjmjyk6HLGpPpsegQb-f9u_GSg8EhUQuMWr1GYbHU4jawm9WtzOOh4","iv":"DGyn-kYAyVxGw3fJ1pGZ8A","tag":"AeF6-aceyQDUOtJreAS-BBWjGUu4T_re","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ2RHdRMXc0eWhZY29QLUlSX05zY254bUhmRnFGdWp1bUFFTWVJaVo3ZVJZIiwieSI6IjJyUHRWVkJiZmlwN21ZMTktb2Q2YjdiX0w5SjFNZ0FfQ2U4NTc2VUQzbDAifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"6c67kMrZe11m540xts24zTVGWeTq-H8MTIzWW_pRVXcrGEHyc7N4PeZHngPDY_Mxi1GiW1r5e0s"}'],
            ['input' => '{"ciphertext":"lKWsvlYaWoSsnw-NuywVrHgp0LaC8_g6ZRcCHJmnCErqApTi4Sn2sfz9Ew23xguK3qH5bwYqhqQQSpihQ-BLMZ8XkUrwWTPcp6UsQ1QlEevaBi9_cichIl81-HQyPINgIM-t6klxXK9X2n9DB-BKmhVHYbdwyBsHvWgbS3PHOyBKwGa-pb5thQLcPC0fJn9tRmCbGXoMuAFLtm86TFq20hMBoNNLmwW122x--zz8XUg","iv":"FXV6iLlbpLaFDFoYgUo4Ig","tag":"5aTUQ9M79YYJHROzeQozQI6QvUaxqYPOOomrz7s7CuE","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJubS1vZ0N6TmdKUjc1MHdlWWlFcnRHNUE5Y2U4X3pOYWp0dFozcVZfeUg0IiwieSI6Ii1ta3dKU1pidTlFV05sS256cXBQRFZkU293TUpOVXA4Mmstc1VVcURZbHcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"NNqou4kIX5HdcXCauOIg8T2gj7OMnZs4fNOuKBV7C1oue44ctUO6wZfbh5U-0pwt3Y4q5l73JGCisLaQICJGVnRcFmk2ZfHo"}'],
            ['input' => '{"ciphertext":"F_zLcuR6OO3TBQ7uouORvGAvdNT_6eMt_ck0U-nXSQ5sqMEgKYuFMP7FMLRYTKZyzYQjj5DNCntbdQb5_31ifDCuOIVIRG9SsD0M9ZhKEXm3hM9pDCb90MbC3FD6fwcR6HbQfriq73WmBFbM1xtfVPsrAnrdNRlAaSJtV1Owf5yAvv7qx0vebMrOAOi_SBO0Qd_Gx9RjbHHEEZG18a_ZlLgwfrP1Ihs","iv":"FST1A5XpZBVfvn0B","tag":"lH1Q_KJUrPbp5r2n0P2WIg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ5cFhDYXJ2VUZWVS1CeDBiVkVITDZGRjZXQ3dkSm5WMndfa0NlREFnN1hVIiwieSI6Ik9hYWdraDJ1ckxZZkRrVWZQZ1VhRXNCcWs2dDBHaUZWd19BSWxjZFJnZ2cifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"tzWnuZV3HCXQbXSxkN6TryKZVVK57PHE"}'],
            ['input' => '{"ciphertext":"YJDo9qQwMeCiCqiJykAPUae1LPzMTGq7DoxaV9bagXlys1Z_SZqek70xY1gVH2Q1vV19IPuVHQR4gSt4yFv2ePgvVXA-xegNn5qxIKznA_i2JaIMAGUp3AqILexDL6G6ZUtd26-FWTuTxbCs74PU8MnXFikRzPUg-G7fEl7VFusBdGFpJMWRGPOf_ks1o7qsJ9SwWILm09cg-ocGdlxeExDSXQmv90E","iv":"So5obfP02IyBbwEJ","tag":"r3L8mDu9XB7um6nqIiEBbA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ0cEFvWng5MDRtSGV6TTRWRjNVdm9CaGxXb1RLZDV1NUFVMjF4ME5YNVhJIiwieSI6InJpcEM3SFhTWEpYY0JrdHZJREd0MnFrY0RvYnNUbzZ2WGg3MUdyazV3OEUifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"0cR22N7j0lVozgmmL3btagXSeM7CrOkVPJ-XPTrxq9Q"}'],
            ['input' => '{"ciphertext":"HODrPL6IRoK0wuith9tf-LauitCaYxthq_l0DKwT6b8ez0uxg6EDCAK9tI0qoU6ajTZSaULiRxZZO5L5TJ6rWg7uCNO6dKWLmBNjiHXqa2GrlSP4KU8CuaIKvmUYO3CU7YvrL8MIOxeSTzV4Ka-uYx3PgBHYpGU-wsqUFF4r-YEzMbzKZ2nwdaGJo4E6CWWFrJKhz5UJZ0YdeLrZl45cN3W4sqDNvBE","iv":"4Fjj5FMKqndJJyk0","tag":"L68T5CnQ8aWfs5sodrIn-g","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJORnA3YWZ6bWM4ZlBIc3NwNUwyNjU1UktoQ2VwTG9PZjZyVk50LTREYThzIiwieSI6IkVJOGVrTktNbXFUeXFsVHk5YWRjY2xLT3JqYzFMZGh5LWZrXzQzejN5U2sifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"nhk7cste11u4dffZrnc1j4h5W33sZvq9WSAplivutVp0CQe-lZRHKg"}'],
            ['input' => '{"ciphertext":"GYce4M2vWZY8CUCr53v-mKvCqCPofaopLtLBrZJ78ddZ5pTdcR66t9dG943IyzdOEeEuRLp_4ynpyyXR0GWkiMmj7kEZRFPRboM5XzmeOomcnUAVW3Sm69WBYFLzs0DAottiT1RBz4S3vHZI68hhXF6NIyIFHD-8jD3zSlGzN_ubaEaWLb0WrlpSnCMm50T-zwuofyQtIxca0mkOWag4_AYC0bDJRxnOJh3G1t_X6ow","iv":"eFr9ZZlankeXbKpd05JpVw","tag":"LN9E6S9vjgqcOjq3-zrvyg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJDWExfbUFqRUhCaWVRazBHOWlyNzZ6em5RNFd3Qm9TdXRld2l2ZWh2YVhJekh3YS1UbjRjanJmRVZJS1J6ZWN2IiwieSI6Ik9sX20yX3BYVFVWNDlDbklBNXpMMTR3R2IxT203Y0U1VFlnaG0zRGtuYjlHb0RnTUJGVVFwZUstR3VJWHpYOG0ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"vJ07JrMlgmu-iH6fbq9KJ77QGGt8w1V899c24zNThQczborr2uEsig"}'],
            ['input' => '{"ciphertext":"l3wx9_nYWMb3JDPKA5gwEm_rjdpgbHO5qLhuz8DXoLjV-lLYculNw9FWS8_nJ9xC_xzBP0-IpjWLAYkGRXFZ7lbGHfDmQkWdUJsy_obgT945Vp38hwEqsstWFJO-7c09CnJYl9UVzP2grTg3oAM6TV__ZHg6ITHq3OsixVHJTSnlh11VRCOP3rjFONpnUJtDxoT9VZTR5goxj5hgwFGpoj-xcfmIFK2wiRehQqgPLPs","iv":"YQ7KrEk1MkbaTv3hQMwbVw","tag":"TdR4YFqBGQcchKlBgxsI4_m_1uzHx7y9","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJTS3NUVGN2VHB0ZFNPcmxnZ3hNakxVWWZyZzdZcE5rbVNuSG90a2ZpMU1LbER3R0VoLXdSX0I0T2p0WWptVUM5IiwieSI6IkZWY2Q2bmNWWDhBZUJiTEtiMllheHJUUlJoVHhrczNqelAzUnlKdHliSXRjSEZZc1NYcEFERWlTV1pzWkd2Wm4ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"AtxkQKn58RtEUCj1hxL60bji2uB8IvbUWqpDSM_s5L-TRa93jnSptN0pRDyv3CDaqAPgrOPd64o"}'],
            ['input' => '{"ciphertext":"wZb26S54HHh970h3uuQ_t7zZUWAJPBTdLkps6Am5lgwzDEoYk7jz_xHt4PZspPaCgdJv8BDxvAZw-wJ3uSu42Rus6uAXNOm_x0hHDAFvKxw-uyvnWB-Afp_BDpdjjOuESwVrP-QOSKVfVdWiR57J0NwQ3q3JOKAJuH70GtefdJufCdEN-WhGlJ-PM82D4TcWo-ZK52PoE-M_bktCj0h3FekNmH7NBuB45mBTHqshCnI","iv":"T6SPZ_ZNi8RGWpcRN1Ht4A","tag":"y1IHOEbLxyYvI7NIRCEaDi3HWon9_mOTdNMz7Vr3DzA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJzOFg2WDNjYlMyVjQtb2dQQWhjZW5YTGg0T1VJazhqZFVLdkFCdzB5YXlZLWExUGxNR0JuLTk4S1hLcUI0OU1GIiwieSI6ImV1Zm1uN2NaVDNzT192d0RyNjh5WDc1UTVXSm5mRGw0THVoSjhucF9LVlREZ29WSktyVTJhVDVZVHl2SmdmNmUifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"Bkx_LYfu8Oq-VrhX5WaWmNwafhCyKX-UWXdF22pX86PHaKaPwR60EWFapuCfMZfAK69RShDv0qWYhqe2AyGu7AWmz94Q0HVn"}'],
            ['input' => '{"ciphertext":"yfsGSfJFyDHot5QyTfOssDQaXOcLGKGL8Z6pMApnCpmqLIUpghj8uIS2eLmKSaS4S2v-pcQ6nIVpCet1FdHLbGOghQuRzfUz24nBJuJ_q4QP8A9dCqfZEeRqXmRXoEbEQUb0H-TuSlLO6B7zLPWno7I7hm6kd93vGlqzpUNFnpJ4sCaNoOhYOQhb82HE7jHpi2ZLThOGWaV_ES8qa8jMAJRoV7DECTU","iv":"wUSgo24M5Qg_d6ZZ","tag":"4YpxsSQfzf-fcJS5Vl6t_Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiI2R3ZrT0VWam5MVm9RVHF6enpTLXFHUktFRDRTT1ZxQUZ4V21mdW5ieUlMX0hneGx1Q1RIcU95YUdKMkNjNEZvIiwieSI6IjJLWWRMMmx6ZmdlWVE4NURlQW9lYk9VU055RmZHd0NGVkI4VUVvMlZxN2pQSW5femV4MDZHME10eW9rUnYtRWcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"2qqa5QibBfaz3nxk672G683yLNyJYV9F"}'],
            ['input' => '{"ciphertext":"TNqwuqUzTB08s7Z7hfq_OyHsNCvUVp0Xxd3kdD0YFjtCFk7WVWn30Pjq4nB7cnHyeqPqrg-Fo4h1NRf0lb7Zs1N_zLgykncOloskS6BS8AhwAq-W2VSOI3r5QLqqfpTSAwSOtzwrU2L4HB6_ECxOK84z3g4Ful42BQZIWZWk8QFz8PCmbZNYimFPgJsxAFjuFLpN1Yb5o175OEOWjbRzOKyUcQK1OBk","iv":"Q6AywXdiikOweOOt","tag":"sTJ1Sm40q8pNITtcCRR1Cw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJoZm1jRmNvNWhNM0VOc1dXMVJIdmFnN0JDNi0tR19NZkxPVURPazE2ajB6VkZYb2JJS0REeXhDdnRaaFN0ZWxTIiwieSI6InMxR2pJWk1LTVYxMkQ0XzNjQ3dCeS1ncnJyTEZpSlVOQjFtWnVpblRrSW1va3pNamxnbGppMkQ0YTRoQlFLWk0ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"g-aHetEzX4KdFm4_Nvu9G0IrAx_5KqVW3-4FItNh7Ac"}'],
            ['input' => '{"ciphertext":"oZOcfdA_CMch6AnzcdbOrCoYTl33Iw2FFDvtv2dxlyARM-0bNUDZ0pBC3Kdih8NiX-sVkSHVP0h_AulUcZcq0DDCqx04Un-GXaisRouJFQXiM6sGLYuCCqXGBzGCs48b_V8OVdo0-QLtfjO4rFs0ENqwBdBDOlAr4IwYMKbvzQyBfM73_CZ6lqC5CzVUwp4esKqUDwEMW4GKllTxhkQ16g5V_342fxI","iv":"Keo2DAQHmBUhz5ys","tag":"Knq8qFH8MD6m8iHnsAtjHw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJUb0gyeWQxYlZHUFpUdFVrb0NaRjlYaTIzTEk4WXBUc1lUNXpSalRFbkJTdmN1a2M2SnhjNDhUc0RxR2djV2NQIiwieSI6IjRHb19ycWpDMUhZNGhseWlaTGktT0poY3BCUFNuOXBHeXltakxMTVlTMURPOTNGa0o4OHgtcFJYSk5CSE5BcDEifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"rDj5fMM4frMBQbFokE9JQ8p7QEA8RWlYwf5gwtagaLnxYEkJrvXlnA"}'],
            ['input' => '{"ciphertext":"0yIJmTaLfA-nnb4FpziO5DZVjX4eHkKPz0Fa1tG_wFMKm11JGa-HdiYXXeN2_dORth7NlhhEcIHu50kQL9u2rFe0E5wFZ3oDDp-M5DTwKjQNSKGxfzIaD4l2fT6Ou9YgWXYMBuI9b7i3gGrOPLPFc5kuVpKrHsV6ynXTlgmMc9NyhQpt2WFCH4CCBohv9LpKQu0hx_U1nf6Q7JXpr79JKU5W_nCwIyhmhaKmFNs1Zdg","iv":"2NkLaDO6rEjiJ6GQEYCY5A","tag":"YKTqfroqK9o0OYtsPl-NOg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBTkFlSENrQy05LUlXeWlzeThHTG9yYjZYb3JtMXFIOGR0TTBVeC1YWV9LWDlqWXY0bk04VUdfa1JkS0hsaHF3WUg1QnJ1U09oUVBKZmNYVHlxdzQzNGEzIiwieSI6IkFEdUZRQWVRT19hdF9xWlE1SFJ3aWlkT2dmaGhZMVFIR0pOMjNUNnUwUnktSHlFZ3l5dmhmVjhFVUJZcFNUVmNKblJBVTRyZzZST1ZkSG4tNmFEZWpCVlIifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"2P_Hjy1PpS6TJN6zjzx7dQSDdy4OFz7qCzvEv7PZkTXfe9dNkHTvAQ"}'],
            ['input' => '{"ciphertext":"Y1ld7kIgk-lvVL3YoW-qO8WWfXi92WmI24b5gCHMD1TDXcQob46ldsqQ9J3LSohrm5VqUbHg5oSa9JBW9W0uGzZdvyEDEnUYkg2qY4o-el7-Wnda8z9rm7XCO8xK6IICPnOSMSWiu8A3rwn81nHKOGHC68H7WLazCZgaxaLgmgLcP5Do17Wgi3carjjxm4iN4ohXSGA9ZJDzHkNsT2V-GmMzl4cKbyGqD-SspzfHsIA","iv":"4hkKVXthg1p_4LIx658vqg","tag":"KlLLT77fB60fxfRUYoG3-BNTgP8_D19M","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBT0l6SlM5cmZvdGxCWTZweXpKNGttQlpuMFdFN2plQkpzVVFpUWduQzQzNjdyZW1rYU9IbFI2cFZoWlNfZlVMSnVvNXo2SnBKYzNGSTJxazJqNW41TkVBIiwieSI6IkFCd2ZjQThzekYxVVAxS1ZERmFiX3ZJQXo4NVVtVlRRRlJpVi1lckZwNFBHc3lmSUNyZVVNZk5ISHhFdUpsUEdJN3RtZWpUcFJYVjlmRm41YWxScVZxaHkifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"ju9tngs61CQuw3Ii9iXY0wkrz6TocdyzvjG7PldRiom9n8yfL8ZB6cQsDzHsrbxrplQfcyMc74I"}'],
            ['input' => '{"ciphertext":"QeGhuHxKId6XeFggipgUpvwn-xLZEpTOdq2LnBq9KQ21uLdkcbLfAQNEdRdilIspMAhE6WzqCKODowj2EyBOVWLddDqn8wff6OXEv0_5j_zqJDJBXVTTxWeip4FkVnygHWO4VG0VW_XLQR0k2JAShiS_uR5sAZwT9CJXlxyQV7BcZSfqfpLw-eJtWe_mhgTbbqFrnYFI5Cf5jI4Hdl1c8E7h7BUrwzfgnPP6TXjyxoI","iv":"CYYW0DMM4pUOtH8iA1T88w","tag":"DPcpOlTfxxTFbn_s4VakwM0lby-Fp3yBQxd8nM2JaDU","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUm5qRDRjdlJEenREdnF2TW42YTRlZkZoeG5DcGRqRzFzaExFU1BLWHNxZDFSbUdERTRqZDN1ZVpZUFlKaGZlMEhLX2tKQ1BHMmxpNE5HRF9vQmd6eEdEIiwieSI6IkFibGQteWtadjNnei0xaXNvMkpqVTlNWnY0VENscVY5T3E5ZVZuQktWWTExSVJDc18waTVXY1JNV2lnS3NvVXVwR2lOUDVTb3Q3REFBSkhoektQSGxacksifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"gLE_kfglbHj0lkBRrEAIouunrpGjomr4cCNSOYeZTOLtphojXyYB5hhHQjwnk0-FmMIEj-JHLVogstn-qY9keVajYAMqf9Rc"}'],
            ['input' => '{"ciphertext":"t-U9vLZqvJWJdJLBXuYDR4OO3mqBVfc8ITGXk5ciVFsslWTp2fO7_yFdcEcK_QX2o8bg0YTa5Jl3EjYKDSA73u3_KzzPJMLTWD4wYqL8LO9MM7H-Fuu3y6NFggqceTX0CJezI4ZoiEhhhWJSy3aZBaQlqtIKUI4xGe-tnUgjVuYOS9JaDgFVgfQG4EFW9zFDFfu30lkKYKMqaPth2dWxFDLCFwX3yVg","iv":"VhUPBzS216Xo5H_h","tag":"t9tPsHH90Ary6G_jmMGKWA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSjhoNGRTdXhLTmRLaVpWZEI2QnctX2h0TmE0ZFVHdlZsTGRvd2hjci1hR0tnX0VYdjNqUFZUYkM5OFIzbWpTbEh1bU5OZUZoOEp4cG5KZXN4RkZpeWlCIiwieSI6IkFEb2JvNzBaOGRYbFVQdGNZMHpKVXNLZndram51OEJkRXRDZDlSbmxFSFpxOGtMd1AwSDQxdERyZENGYmJ4MWp6Y1hUSUNsMzBxSFlxb2hvZXFrTlBHNVkifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"ntSlDVjrsvlVyGPqWeMIr7g_dVLCDivi"}'],
            ['input' => '{"ciphertext":"l6zDd7w1JND51dGDutFYoxn-seZdShpYz5tlFr0KsllMLPoi6wEpeGywz-1BTU3-e-BazdTB7KPlVMmb6F-rGCD7h1rqsxlZU9JH_Zs6TjspqQasMTKVOl3MH_oTgMKS-DI60lFmLUAj-KwdXjIVTPqqSEmxXxme_udtQFk6LNXKkIAS_u3rXObfbG_WA3xIi-2ZiY8ea2GOl42ZIddqpuFc-teiGYw","iv":"X4YYyKC6S2EAq5e7","tag":"SYFTMuHqADqfHw_mUxX8UQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVlBBbERkUDRpbHRNM2pKOGVycDcyc0VqVWVmLV9EVXdZMUt6NjhWZHo2dG1RNDJqVEx5T0NsM2JsNjY5bmpHZnhDeVRieVI5VkJ0QWlDcGFpWENrdFZRIiwieSI6IkFYVDFPWks0X200cjJSOHYwUlE3cEZPQXZJV1E3TFhsSmtyOGo0dzJrQURrR1JtR2Y0a0xLRnJqUXZ4UmNGNFJ2dUd4YWtMRlAwV2Y0eHpVUjNYc29LZTcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"5dMOaFexxy32yZuMhgqO6mJEGdQ16_rw5etgRSiH11w"}'],
            ['input' => '{"ciphertext":"zHKGZ3lcidk_ED9M9NHr-CgZ8i9OWMXo3IKWaxmf5f6w5Hy_9rrbY-E4NTyRi9pySEN6Qyi6gIT7n6nFWeROLIsOpp8vRlKRbkmGnOjbUs2QvjGiH8CV81HRvYCXLa6DwFUI_J9bmAhuB79CuEVBzxE7F2IT6GNimxxkW5Tg-Kwc_VL4mboOkE0ngHAdTdWQJrVzNFINl2E3KEYsWtY3lbt1pojH6XQ","iv":"i8SZR0geZRtCWk5_","tag":"tP_C7rRSn8mqUVD29r9LUw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSmZyNnhibmpjRlZqQjR1TkM0MTkwaTJNZ1JRZng1NXhlY0tkZmNGeTRmY29tSlJqYWItSWRHQTFYcFBVN3VUSnpuajI4RXBLSkttWFFnZEhvTHdja3FSIiwieSI6IkFiOVlYbENZQWk2dUhhazRWV015d2pfdFcxUWs1Y1RabS1VVmZtNWRKVUZTTzVHZDJZM3VCZklyY0NLZko1Y2NLLXl1X2NNanp0T0F0TlRvS0IxNTE3M1YifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"jr2rPS0sxlRi_oeIBT0B8XlxJOUZJREKDpJd0FoAgRM0OsjwKbwRow"}'],
            ['input' => '{"ciphertext":"86pUnoLJhflU8LURtiF5RjyZKa5QpppQaUkih4huZDYR6xAHcb_Ou5hl7GHfMvWZW8BkeaPPV3QV4C7jcFlnFfyHdGDLE7KyPzEQ_YMHxzhG4LsO_d5PxMaQBYe8cJJDXvgaE6_8iXTlBxjqxoNuETTr5VZxQtrP27m4j2lklykZibyvFydZNGx9lP-QUdTM_hv0M-M7_Zy2PXHZJsrhcyPgUAVtVIOLxoK3d0nL1e0","iv":"UiBIMQwpjZP6HyfxVbw7MQ","tag":"Z5x6KIETZMcul0LvFufeKw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ik5KUFVVbHlYem9RSE81dEJKckFEOWVnZXVsclZCYkJwMXIycUY3UzdNbm8ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"cM5amByozetCbGao__aREhlUcJdUIFZWqBxcSa1WeYAUeHaA8welag"}'],
            ['input' => '{"ciphertext":"ZYX7Y1H0tmnso16nn-9s_Rhiw9E0CcjpKn6Mef5UHZxvZFFZlH-ndeeMi-T2O0NLagJcA72dCZycelmKnQ3B_junRnj0pg_1Izy4_XagmWL3T2bgZQY7RA5YXBzNbZrPV_Tfh93STo3w1CoDsYGJ5KPh-cfwaKXRhzCaeaxLbcSES0LiT_4Xpr1f4-XTwwyJsnENoxNrTX_GMqNFHC861HZhcY54pDBrVywXn7_TiIU","iv":"E5HkYh-_3Cu7b3J2RDp1Hw","tag":"K_Tjr-bxbTGGrEgZ4MyNJmbo_QppAKTP","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Inpfd2ZKVFVUU0pjUFROWkkxZlFldGdwTWI4NFU0UHJhZFgwWm92NDl6a2sifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"8O9y0-Ugge5rEp3-mpVL3oL1R2uC90TYQy7f0-wa9tuSFAF5vi5tg438PTfxoviFGHxForj3_VI"}'],
            ['input' => '{"ciphertext":"yK78enqyEQEvwujprdQ00IT9eyuKOcA4_VuUaogLJKxehTZRSznsh4lb0RjWomV37v-crUbUklvxXpaKYd0W6xN64J5VV2c3lqWn5-7FDspDLn5Hrsi0qX2RuJvhr4-2tiL3QCxataw6MtiVSj8ib7d7BARFS0lorRXW6S0IVwbzdyuasHIul9W4hx_ervrJ4MHPs83KMWOZuDppXjNj_ym46VpmC9XpWxfDVTyKlKQ","iv":"O0hq-ZfavALet7EQdKPtPA","tag":"Q2u3JBdq_mJM8vOnhw_MLZWw8OHrerRFcO44m18Fnrc","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IjQ4NDRSWUpxQWQ3Mzk1YmlrbmJGZHpNRWJZRTk1UXU1TTZXY2tsejFublEifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"1hnj3G3e8zqJMNyW2JgLtQvr76-idfysmqX7Z_K5AAxpen6UmT4jwfCxuUjKfdw1k33u7hz4U6hTCgRDzvIGhnpwAWXKIjaX"}'],
            ['input' => '{"ciphertext":"pncq1HNXbejvYCVFvzXn2I8XwBqE3ol07_qus64hlEIb7VcOxiMl1t7mVo4lsSEyipgYZCFxEVgR_C-auI36XdYqvKCQdbzTFzETBsb8y6WbBFQjCupYUa8IkDRsa7ZaT0ooy6meARQoDsomSH0ubEXIBSowJpygNjkBlCTmwP2RyWYKYboyjK5awI6nTDM92a3ZfFxdOJ2dA3ydlaJLicVfbqBSIlk","iv":"7m-i5f9Wer32W6mU","tag":"36R98AoUarAAJTTyuaBikw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNTQU5TZkJucGtQSkZyVGw3ajNZYzEyWjRqU3AtR0NBWUJvYXJicVg4VEUifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"M_beaZXdtVd63YAMgGaUmLxPzqCIVO-K"}'],
            ['input' => '{"ciphertext":"gVrYYC1cq5Q7aV9QTBeH83R7PTbXnH6tHRauApdcn-Knd5W6j4TyOM4wtSldO34ycjB_o0dsjZ_HPHtMw9e-a14qT5LQCeNDSb9cMb-MU399HDiT5QQ5kst0MX_ZpJXGvNx7uwAWYe1Rz58U-QG6J5J0wiSwqPtpI4SqFEXzrf88PExpLkiQ23IEjW4CnCmDrKpafaE6-ngKzkSmoc3j90Hh3NlIsdc","iv":"d_xuS_WzYJJsACgD","tag":"632n9At2zamWTVRGr08aKg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ii1CS003UTNZTGZ2T083NVN1M2lkUEhFTnNfdVlBMFgwdDJZU0pXeHo1akkifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"OEJ6fL_dz-jXjfe0w3h1yAWAkUC0Vd0k9hgtf5iwfqY"}'],
            ['input' => '{"ciphertext":"zk3qRHTYEdyLMh9JPEDaicjGnieRpP-AOKMNJlPioZ1w2WOR5Fts3356R9dDGxI1HuUC-g6_D5kQjROwxbeAtycj8G4CBQVhh8f6bM2eXNv9SgIyIePe6wpc8NcFNJ7mx4TsvAKly2RR0b67u3n__tUkTsiJxiVbZoRC9T4Ez7wX-TmphmFRLtsMQxxIdJEcFmUkS42toechllYS0EjqX-Yeqb8MAQM","iv":"UlDeGbl5QXgpTOUn","tag":"gsupckNy1QZFPqDVfYhkfA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiWDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImE3MjhSbEw5a04tX0JYOHE2OS1VcHdqQ3RldnFCMHdZYlhhMy11eXUyQk0ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"DNpDD2Q3JEgZce6kP8lt-YPcKf0HdSiHvDeM0OaQ4-j6YkPLMBZ00A"}'],
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

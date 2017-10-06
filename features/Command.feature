Feature: The user can run commands

    Scenario:  A key can be checked
        When I run command "key:analyze" with parameters
    """
    {
        "jwk": "{\"kty\":\"oct\",\"k\":\"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g\"}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    The parameter "alg" should be added.
    The parameter "use" should be added.
    The parameter "kid" should be added.

    """

    Scenario:  A key set can be checked
        When I run command "keyset:analyze" with parameters
    """
    {
        "jwkset": "{\"keys\":[{\"kty\":\"oct\",\"k\":\"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g\"},{\"kty\":\"oct\",\"k\":\"bwIAv5Nn-fo8p4LCEvM4IR9eLXgzJRs8jXCLb3xR0tDJGiZ46KheO4ip6htFKyN2aqJqlNi9-7hB6I1aLLy1IRT9-vcBoCSGu977cNAUuRLkRp7vo8s6MsxhB8WvQBDRZghV7jIYaune-3vbE7iDU2AESr8BUtorckLoO9uW__fIabaa3hJMMQIHCzYQbJKZvlCRCKWMk2H_zuS4JeDFTvyZH1skJYF_TET1DrCZHMPicw-Yk3_m2P-ilC-yidPPoVzeU8Jj3tQ6gtX3975qiQW7pt2qbgjKAuq2wsz_9hxLBtMB5rQPafFoxop7O4BklvZ9-ECcK6dfI2CAx9_tjQ\"}]}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    Analysing key with index/kid "0"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.
    Analysing key with index/kid "1"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.

    """

    Scenario:  An RSA key can be optimized (1/2)
        When I run command "key:optimize" with parameters
    """
    {
        "jwk": "{\"d\":\"JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ\",\"e\":\"AQAB\",\"n\":\"gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw\",\"kty\":\"RSA\",\"kid\":\"test-key\"}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    {"d":"JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ","e":"AQAB","n":"gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw","kty":"RSA","kid":"test-key","p":"pxyF-Ao17wl4ADI0YSsNYm9OzZz6AZD9cUxbxvX-z3yR_vH2GExdcOht5UD9Ij9r0ZyHKkmWGKCtrYzr-Qi2ia2vyiZU0wGmxR_fadHnkxfIqW78ME5C-xGoWLBtHlTaPCWSEmv3p5vM2fqZeUdqTxzb0bQABt0fI6HPjvBlI0s","q":"xiSp6dbdYGINxtklTJlzVr91u_GJzWqyyA4t0jhuWrQN7dLW0s_3I9x6Pdk5U19j0iLWBwcutY9e5SyWPoF0lYVIowZeW0jNiOtv0NthayJ3HJpPk8kj6sVlH0y4sKN_WWHhU5leTwOpr8IG-yohKRyV6Xwhu_JLkzKKWod21QE","dp":"pYUyCNGMRDx7uK4BhbEP68zWIAB4_K4w6lS4nuQvRDJdpUjh-YVCFECUATwSviZVU-QXWUJTwgb8n-byH9OKgeogMTkwUWPUXHHKZ1T6a45mObRtZCdQXsBJn7b4Dc_77RFFkquQPFqsV8fI1gBvgvbRn-8LC8FfQ3rVS_4-Hus","dq":"rNTcNPFLhj_hPnq4UzliZt94RaipB7mzGldr1nuMnqeBotmOsrHeI7S0F_C7VSLWgjwKrnSwZIQbRRGAOCNZWva4ZiMu-LbnOTAMB4TkU7vrY9Kh6QnAv47Q5t1YGBN1CLUdA3u6zHcocvtudXTJGgAqL1AsaLEvBMVH8zFIEQE","qi":"bbFp1zSfnmmOUYUtbaKhmFofn0muf1PrnMGq6zeu8zruf3gK9Y1oDsUk54FlV0mNBO3_t3Zbw2752CLklt73zesVeF-Nsc1kDnx_WGf4YrQpLh5PvkEfT_wPbveKTTcVXiVxMPHHZ-n2kOe3oyShycSLP5_I_SYN-loZHu7QC_I"}
    """


    Scenario:  An RSA key can be optimized (2/2)
        When I run command "key:optimize" with parameters
    """
    {
        "jwk": "{\"kty\":\"RSA\",\"kid\":\"private\",\"n\":\"2NRPORHXd7wPU6atHqmSfWgEPvsP8HVUkY2AwQQAc8x1J509X5HFxeSXnQym9eAnZHl0JCPbvHoPH4QHlvITYoh0MSgFm2aOPyqOD-XcNdKWtnNX2JIurUCyVlwSwtlmy2ZbCz8YuUmFO0iacahfK1wbWT5QoY-pU3UxnMzDhlBslZN5uL7nRE8Sh_8BthsrMdYeGIMY55kh-P7xTs3MHzpOKhFSrOhdN6aO3HWYUuMAdoMNB-hJvckb2PbCy0_K1Wm3SBHtXn-cuMIUF00W9AR3amp3u3hLa2rcz29jEFXTr2FxKyLH4SdlnFFMJl2vaXuxM4PXgLN33Kj34PfKgc8ljDJ7oaSI9bKt7gunXOLv_o4XWYDq91cvUkOIDAsvqxzzHPZBt0Hru7roW3btkUOiqR6RWy-Cw272yiSEC5QA93m_vklD1KajoFeWN0BW2lWGlfGieZldvKX0sumk1TZuLhlHPHSKYcpeCfahT-jLr1yAeHql6qRN_a0BiHu-SSSjts6InmF1pAELznZ3Jn9-QXX78LsY3xaqOlYqHbCohxXorlYRi4so6eMGILtXjqHOoISb13Ez4YNOQmV4ygmyABRkE0AQG5KLy5cZB7LZn7zqw869UjXxWrmiOaBeDqOkxww6qiWIEDwPIouRLwOfPFtC4LGlb9LmG9Hlhp8\",\"e\":\"AQAB\",\"d\":\"PsMls2VAsz3SSepjDg8Tgg1LvVc6w-WSdxc4f6ZC40H5X2AaVcGCN8f1QtZYta8Od_zX62Ydwq6qFftHnx-vEMRirZ_iD5td7VbKDDwCw-mTCnjUorGdpTSm6mx4WcJICPQ1wkmfRHLNh916JxAPjCN7Hxf0iu9kme3AUJzMs-IvrBQmFZ3cn18sBAWCX0358NEDoSDBYrhmpwZUnvTe8uMToQWmoroX0XX6wEGht8xRY_yHFxTb032U-_ZhaCxOj_uru8bEqKfTm39CBYSg8j0gu8LZqYAmhI9IHxsk16OgRJG2CkBlDv0yYk799dUEY0oUfs7Y4D4SoeKe7ZWMHgKMEqa7ONz18ORznxqKSQhi4hfNVgwMzaM0IoYP4KOfHuaK263zhJU0hMzURJ8KifECeOsDHBR6BhLJ9TYzUe4c9UU55nFNgRBwknKHFFrRAsgVETEzmZWHzWwGQIFtKIAVZ1cjkdMEL3BlbzzXVofXfbbCrPQqcABYx2BZ-J_P8-UFjeMo83VLrR5IHj0_8IhQZUmxZYJcpTIwrf-1A4JGlN2_eLqRymF8tZI6zIPJyo1C0M1CIB3EeHzi-70SbF8xFtGUB7hR234yo_SM-KqVdIk2Sjjta2bQ1KXjSEcvrS_358AMiP0-9JT_fHxTCyzra-SNYoZhdnrEFzoVwQE\",\"p\":\"6fWvnj34kJtfMnO1j-qbPjFnaTevREBGAypMvUBU3Fx1Xx0nE7zdc7lln2Qq5-yTQtOQ2lpiE69HkQLR4pMU6V44SjFgVzcTzbFCnNgknEV54S5dyp4KojSWxBi6bt5GwaACkiElDEw9wgc-8JgaEkv4F7e-w44HBwPDECTjE_N0vIawpbD_y6zpifB8ziaAI3xTG4ssA1dt8WZuyQW8SR4FRsYnfkqy0twwHn02gs7XSl4NepkhSO7CY5-YC3U6LazAEZi2NTiUuZSw7F6KaRhsA8CnXTDE5JqFks_fXfLNCbtClON2JtrB1zY-l-2bHyh2a6unDtGn9ZN-Ec7BXw\",\"q\":\"7UF_NblAyTxmj7Z2Jz1sZmz-Q3YHOcta00DjmHBhR9ItYRMQFMj-SUGPAtwvN-sk3_ThugaQt46SLT_I3Gy8433cHdW7o3So6HiMYVunyfhqnWznSWs6SvIoEh8rJOXkkIZ-DlRP8XyW5OOvi0cbWEQ1f1jbFyistMmnBClPvf2TKKPvShUl9qmvLxuU87j-_bgQmjVmtwZadnPOyPAxQ4_qqSfIiTOvMSxSycr58rTyu3khHQapGHkS5-2Y_w40GUSfVJ3XP48delYpK-PZP71hn89MJTnnfPOtvJAk1wbEev5wQFTJd-PGOudkGkuEIXryF4TGxRPltl5UeF0CwQ\"}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    {"kty":"RSA","kid":"private","n":"2NRPORHXd7wPU6atHqmSfWgEPvsP8HVUkY2AwQQAc8x1J509X5HFxeSXnQym9eAnZHl0JCPbvHoPH4QHlvITYoh0MSgFm2aOPyqOD-XcNdKWtnNX2JIurUCyVlwSwtlmy2ZbCz8YuUmFO0iacahfK1wbWT5QoY-pU3UxnMzDhlBslZN5uL7nRE8Sh_8BthsrMdYeGIMY55kh-P7xTs3MHzpOKhFSrOhdN6aO3HWYUuMAdoMNB-hJvckb2PbCy0_K1Wm3SBHtXn-cuMIUF00W9AR3amp3u3hLa2rcz29jEFXTr2FxKyLH4SdlnFFMJl2vaXuxM4PXgLN33Kj34PfKgc8ljDJ7oaSI9bKt7gunXOLv_o4XWYDq91cvUkOIDAsvqxzzHPZBt0Hru7roW3btkUOiqR6RWy-Cw272yiSEC5QA93m_vklD1KajoFeWN0BW2lWGlfGieZldvKX0sumk1TZuLhlHPHSKYcpeCfahT-jLr1yAeHql6qRN_a0BiHu-SSSjts6InmF1pAELznZ3Jn9-QXX78LsY3xaqOlYqHbCohxXorlYRi4so6eMGILtXjqHOoISb13Ez4YNOQmV4ygmyABRkE0AQG5KLy5cZB7LZn7zqw869UjXxWrmiOaBeDqOkxww6qiWIEDwPIouRLwOfPFtC4LGlb9LmG9Hlhp8","e":"AQAB","d":"PsMls2VAsz3SSepjDg8Tgg1LvVc6w-WSdxc4f6ZC40H5X2AaVcGCN8f1QtZYta8Od_zX62Ydwq6qFftHnx-vEMRirZ_iD5td7VbKDDwCw-mTCnjUorGdpTSm6mx4WcJICPQ1wkmfRHLNh916JxAPjCN7Hxf0iu9kme3AUJzMs-IvrBQmFZ3cn18sBAWCX0358NEDoSDBYrhmpwZUnvTe8uMToQWmoroX0XX6wEGht8xRY_yHFxTb032U-_ZhaCxOj_uru8bEqKfTm39CBYSg8j0gu8LZqYAmhI9IHxsk16OgRJG2CkBlDv0yYk799dUEY0oUfs7Y4D4SoeKe7ZWMHgKMEqa7ONz18ORznxqKSQhi4hfNVgwMzaM0IoYP4KOfHuaK263zhJU0hMzURJ8KifECeOsDHBR6BhLJ9TYzUe4c9UU55nFNgRBwknKHFFrRAsgVETEzmZWHzWwGQIFtKIAVZ1cjkdMEL3BlbzzXVofXfbbCrPQqcABYx2BZ-J_P8-UFjeMo83VLrR5IHj0_8IhQZUmxZYJcpTIwrf-1A4JGlN2_eLqRymF8tZI6zIPJyo1C0M1CIB3EeHzi-70SbF8xFtGUB7hR234yo_SM-KqVdIk2Sjjta2bQ1KXjSEcvrS_358AMiP0-9JT_fHxTCyzra-SNYoZhdnrEFzoVwQE","p":"6fWvnj34kJtfMnO1j-qbPjFnaTevREBGAypMvUBU3Fx1Xx0nE7zdc7lln2Qq5-yTQtOQ2lpiE69HkQLR4pMU6V44SjFgVzcTzbFCnNgknEV54S5dyp4KojSWxBi6bt5GwaACkiElDEw9wgc-8JgaEkv4F7e-w44HBwPDECTjE_N0vIawpbD_y6zpifB8ziaAI3xTG4ssA1dt8WZuyQW8SR4FRsYnfkqy0twwHn02gs7XSl4NepkhSO7CY5-YC3U6LazAEZi2NTiUuZSw7F6KaRhsA8CnXTDE5JqFks_fXfLNCbtClON2JtrB1zY-l-2bHyh2a6unDtGn9ZN-Ec7BXw","q":"7UF_NblAyTxmj7Z2Jz1sZmz-Q3YHOcta00DjmHBhR9ItYRMQFMj-SUGPAtwvN-sk3_ThugaQt46SLT_I3Gy8433cHdW7o3So6HiMYVunyfhqnWznSWs6SvIoEh8rJOXkkIZ-DlRP8XyW5OOvi0cbWEQ1f1jbFyistMmnBClPvf2TKKPvShUl9qmvLxuU87j-_bgQmjVmtwZadnPOyPAxQ4_qqSfIiTOvMSxSycr58rTyu3khHQapGHkS5-2Y_w40GUSfVJ3XP48delYpK-PZP71hn89MJTnnfPOtvJAk1wbEev5wQFTJd-PGOudkGkuEIXryF4TGxRPltl5UeF0CwQ","dp":"DkBA6kqsEWLlcZVKwfFwc2FfAzG5I1cm7JpvAjgg8ytOmvSTpMgkVSA96G-ZjXcDoVZxxFstDjXnDhY14q9C3tQ2aY6IZ8ebFTRu8k7YLAyvV-ATJnxp-Wdqp5c6A_bWKIUuougR8aXTPTZjxxP8wpCOFCPFIvRLyUmZYCpfCqARxEoQCIe3jRiDQTu83nHJ7F9uUIcxryJsOAAdT3Fh_rItcBox3ad_LQjshW7rGxyuUIFaINWjCWZBwP-_qzMA0Ddtm6TJtIQ1yvgbrsozdCNgsPnTOAH4fFRNPpwa5wYbJzSY4ajZUZSRqiJLvcVjZYp5bCWQj36F1JefXkZR0Q","dq":"U07AQDkASqjuyl-jNTwYKA71aPK0rtJ83djXEdvEDNf8Hy32Y5X_0_E1KifuXJAwroLqD8vmXM2u_jx7Zwq3eJnlBITcEhUQijBp-nWYgQ69QPHQdLM2EMLe1x4ipB4lF6ph8N4iBAVfZpecOCeLrn6k2kZ1B7i8i-6Sup9W5Lt5RLfrefPbFLWYUc45iyrWPni3O66slm-grB8V6PCOG88Y8rSJccO4LGgH2dtv0I1A_hsWSX7hOTqqLM38_vIZ0RWLbMbPof26uA4w_rxOuFbjRJ4heqDOa82Un7VteiNiMl3NRImBBJvyKxS8zY7eonLtNtzkfqbx7gtJVcozAQ","qi":"S1WTYfPS8r2BKqQSr7n6_LDxGlRSL9tPISlwjzD0RoEI2Bzq3zeoAD5zTKD2CrHLpkFqTU4yT-fW_2YX6ZtY-qOs3cvfJTaL-650lNALbp0qQK-VnXKepxogV2jSj_dYj6GOLHdSQhVwWYtZ9PDjNwByrOlBGvctfyTa4V6doiwecFUhtuv3BpJu0eJ0_EW90SlvW7wkZdVDR2JtkyC0DSKcmIjhI17V_shPf9JuaVhCVtGSrKTKdaYa0W-Cz-BA1iHP0IIkzINpeKKQ3YihGlsW_64y0N_pxlQYu_47X8_7cCvVHLzCO1ki_T7SGApZmPizYTzV_u6fhiVO6sXIvw"}
    """

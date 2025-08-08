# -*- encoding: utf-8 -*-
# @ModuleName: decode_response
# @Function:
# @Author:
# @Time: 2025/8/7 16:00
import base64

data = {
    "ret": 0,
    "msg": "",
    "seq": "9936",
    "reqinterval": 1740,
    "last_ads": {
        "responsed_ad_data": "8Q1_qpR5jjA"
    },
    "data": {
        "9093517612222759": {
            "ret": 0,
            "msg": "",
            "list": "W8IBAovr0_2gBaXqds14mKVvLJ4NUVS53s--m5ZClSkMA_6Ke9sNE26dCYx8GrDJr3ESqf8Y4rZt4Rh124PsgIu06mfYLmnThL3i3psSLUgEhGgXZAHecuacmCyhlubkxjvjiBp1piTl9ePQiRmHq1VdnTLbnyVWwb5arRung6C1r7hVk925R0P1ol7TUaEC9bGkyZgA3TCi8MXxtxMoOOLq55y_hEJoutzF_1BDAou6Whp4LcgpEfg456-wuK51wBX2FF0HnvCtklcjag5Q6B4ZuDduC1qQ8zSgIUefxBtjR_XiO74KBxk-nZifybMIJdDC5SwRYmTebR1Sl3cs8iYffw-x0TmUOuxb0d5bI13To2eARvNKgBD59P_ugZyAZRCnAbqamaIFz10tJjhD-4NAPF-_TccuV7JNGfJub7Zh-c3YvPb9vmJSEjLU0QqN0FhvHo-DQe4KqG4ON2VpFJdH3OrOUj8EsUD3T9x9w2XfUUaJKYfv2_5t6KF4Dc72WeGbTsv25C6MppqHfouhNvrS3-KbxScP_hypztEdizgsv1GeyoDuL-c2JNn0XQQoRgtTUCx8-I6IoDjiqCXatFV5tGw6_jTfeZS76UDx9BKgOX8MXxajilKgpXSP3p9e1oDRGo71UMS7r86U6AlBrK4d_FHOc01DBQRbte6VSeRKWwugUkvAv88iR6eNY-vPAVTOFNKXIELlR7g14tmCHhuXNd72H9bcOLrjL8iD2ivxaD2s2wmIQshPPMBSplBiOVRc8RgjcyQLRpjvXqzvCiG6Zw3XAiib6jErMo8XpXRSJURz-F8hXCm6j4x-o-ZJb7yLJZL8NIkOf-54_jLgKDLsKXBXI2SW-WOqTsYS5vlSdt4xyQPxt-kQOaXOpcOxT6LooXjgrwJwkbt65pC2Q_hNMzOSdKWtHs9HdLHE67uRt7JqCPKS8l9J2kcz7MiOMywd4szhdI95PwSnDmdoAxBbWBGWHPRsjqv7YfXBMwUmGmPh15zEcNF21rH7IN1HVmfCG3iqeHhp2n623YJsdkFT2kCBsahOXfJ5QyNYi1t6PlnuclYsS_V0ZRIseJFmkHa9zhIqAseBe5_p0tEfyE8nreW-OIXJBCuKSfwaSBgo3XfbK7Ivdw3cXk8QJqt5HRSiNmQK2O9qRohmGlktLFQmXAGPJJrHs_iZrjQ_NUrfiQvwLk29-pjkoC-KT_PL62cn-4IEeTZ3PdvvPlx3roLgV7DzgscVUcXSYty2vt98gfnMhSA5MkuiebSDZs-SvCzKjaDEjLhlJ-EcFVWhBQZZxaWKQFUXu19se4E9eTbkhvBfbnaGKrnVACWAOfqmLBYvzLzhUwocOggDF3iTJlJw0qRuEB1TwSCl418hw1qMgt_qbyMN3FLpsTPOlzivXdGdg-YpwD5z9C6yDQirK92euyIyLnE8xmqUSTcQiXAm65_BCYnGj4zoaOdWpgWDEdZMvFOY183SrNe2yB-ZIJXVcFbciqfTn7JY0C-q7qn6jI244IHDbKQnTacWk7FE2jkM2wrBZ2v9gseHa1SVEIry4PusNpSYmRlae-myb3fJBHqLxkrdOhk3pq86-NC3kbpdyNIEQTd5J37NrY0VH_tL-6W7A9wO1-JXyPFt-MMgWTVs-tDN08StvrOb-ZCJ8GfIZamjCcOF1TXbIgehz0WydkXB80Lv7acVgKpRMgMzJbHDM2lmMdWMUoiJXGDNiYeNffRPU8oPKMM5nYckvvDzokjb5glHaDL-vPXIxUD4DJtseCSN-hb0j34ZjtbsklpEHADE3DBmg82YGOcupBp0gJNT6Orki4NzFs82CuYwbJs_1PPzQtliuAjf4NDssxadW3r8cGwLoQxn0rzN83DiekP_rJLeYzT8ONFXwBIcmd149A3giKzzgqPmT3ivm6HX2m_6AYhABTBX2oqqucEbKIFwijy1yos9cjuj2I47kAE_HM3_TVmKpjG9Q1diICa4XC3nYt1XXnnqV_pLy4OfXsRArApkBZTWB9zwSnVM6MTRmCToihtdXQtfIahhSLs3ci6pBpkx7f7uXBAJdA5POl9axdcwFC_HRMBARzpnmZ9n6nJhi0JET8SPOZoihx9tBhCQ5uesSjmcdGQdfVuLnpA2A9P8Rzkq7xMLEhWHth7PjWPv1DKVw_725o3lADq1q6-lwLS8PeE3Gd08fYFU4Xy8DyDXJss3oRXtlTY97aC2HEGaSijzM_QTHOtgv3DDJ-oId39MMl64sZKC_71VVi1FYD5gJRsR0PP131FCnc_frUQy3xv2_2UUWn4LtEyl8ts9eadzktZb1bch6lVmIsJe_kgX1iW6yzX_W3QdLrxXP-KDEMWXy90cZ8Yi57OPHaWoWof-2ywWdvQ6C3zBy3z3lBnqEjI0r6Dmd3pGETXsHFXNwAvNjuWkUSsCpN3Dhv2vtM42K4XxZL8xxMdpOVaMLNw7-TQBzSjBjOJ0rQx9SBQ2tzhKKJW1sw80xK0tYAW22q3T-f9LVjjvtaUkIo0l0VoIAmNH7TkdS8Gcu_YdcRErU8kRs9PURSYpSdDnUhqknzM5uGxk6fBjEZqeVAQ0-KKe1QMLtTU-WMImOubYgiBn_MOdxm73kyxQu4DrF2i_pA-0efMe9QHLJ4navjOP0FxJtlM3H2HmeV-0_DJSHjC_V8Wj-z5Vq2w5DXrx0M_yPPMnQnrkeuJEHKp4AA6MLz1ckM3rp59XG5Ywh9XXlVVGEZkznZStLe6001MceBxEjYMr4NZIG3Sdji6D66P_JFXp4rJqRBDPpJJPmyzsQmDjtQ6U100lhdmrLv8TKTBesSTwsljQ738L4cDQeUlx8JDxl4o7aKQH7TfPFxPTkuN1gQB5o1wXRKyE2m0YwB13dRuFxE04GKczzJLgJXYAQ0PxcyuyIWNIWWbQB69mWAysyYoF-w-NuOK16bYF-pK9JMBZFggSwDu8S5mseb0EwdQjX3qfwfFomQWQlGHh23_mLpvRpwVoBAvFnobWI0LZ08NZ7YhowfxxUQqe9pWCJAD5NG6nShxTsgbOvgbTwtYcbPY42QXskYu-UEwmonOoW_WbdDpu-xsh9Ynrg8cnSs7Yhb5DnZQ9-M2WaZtDmhWIcOOC0rF1bbNTcOuo40xTPvSh6VOg57Syd-vkGYcBhQJg-sRyG4ab4rBxxn7i2YgW8J6rR7VyWj522hdYiJaOYCegxamcBsUffbBjHiYhR4HEXaJM6Bj3Gka0_42yGZpcLY1qDPHcZi2k9S14mnVaU1cfXoRx72VDHEQfrPYhVKhTA418nLRVwnH0HmVeVjNY68rTnYk3TlctqKhoU5tMC7hr2F6xuXugHlMzX4ai5DZue4u_ZyQ_nC150-a2SZBhn0CA9wxKx36dnKwr4Zik0dMUYnuEemhD_2_dctO4-wNDFbdYR4Z2-1RPvTWDkkYDTV6XRti4E4JG0Ox9DDV9bAQ5u1hlS6L4duQJ-yvtiOEtD6plRRTsYx7VzecwZ3AxkWAlFvZ7anXWoPsC4fUKNnqLgryGuRBHL9U6AYlULvnI5UjjyGQBBWJPIhkwKGyIbmjrCAVoHsRcG_y__Z2K7IsIKQHt6dQPANbpsxm5T5Dv0uUlZfaHgGaOaN_WKYkGBlT1ymC73tQKrVgosvDqSXlQD7OGtNxGLzPf8BUq8E-0cMeZPZsVA6a2esFdLgpABcT8-G6vCsRod6xGYSIbvOMC3gHbvM20HnkRY5qhd2dlEk4jAkucVZ2t0fnjaKfVT3i4nUbHIbc17IPgRQslIeL7BuVsH99duKo4NO_luZDEuARaiDu31W5Tk7JjtBu4JCogNKCrgwQhaIXCNn0wL6ZlHAl0OyX0cTPa5LfegEq6y-bjwu68VvwiDF7swAk3jXCbGuHEvW0rRfzNRk0CkAbuSJMW0DB4dZkzJ77dfvp2eRdVSaW7iJ_bgN1-DgjD4LWHINXHKIMYwan79YoIcoUjYU7boM-xjYiyg31NE5wzwcEhTcdBoUSDAZEV5R8TGi4uayW4f_UsdmZgQhR_5wMs40uO8yXo9reAEJ4J7GToC9E2AmptkWDWFmnA79JVEezfexvC7ZyICLblFl04uMPXgsWHy9OjWzDOZAqrVgI7F9YqIzFCzODYMy9Bs8xj8j7L_v1kjiABw9z-UR6929Mf-H1tiExvC-ayg1V8vFTJdGTORRopRMFGzojoesz65BScJ9vRaCwiP1XySgnX3sBMfrUxRMdqQgKmGwslrsP5aJBfq_GpNu7oIkH5sijTnZykx0W6uNZ3QyysrqG4idjrKhyZpgjHCSPKsE4ylQOpMtnpG6RXrZrg-DoNb0UTJ0sWKxwcu3qtmrDjOZbuYQMaggeGpEB62hJc5of5e4fSW5lZS8O0XF1OZiQ2wH7KIbcUwxoJlyLpHnr1fwJnW68LnDwSDs_EyEiza4-sWzC681tSqjY1Kw9Dz44m63s4sdsNFzyDpwHf4ieYkIF2TVBnaJoz98V01R-nf8F4OaBiDPiLMW3EKfFIaQ59OA6HkcDDz7jiQplW-LCPSgqpeIvAHMueZcDCcXMRXhIWV-l4mu8DuxoGMpgWwJwdfIh2alwzOLnNHIN420kdrmos860nIuRQkKzDe6Sf2G_ugII7BstKaEksabq8NLYSM6hXqkm1JxXSCHaZFNhAhWgJlFzuJg-jrlbgn9C1D9QWsLDHLjBZp_tujPUMjU_eFynFuMZ8EYrN_kPVALL-APaQQo3KTRfChcJZLOgWKFDdHTSs9x2i41fZIVIC30fAikY8fvwBNPNG1cs7KdLXF361P8y97-_5EE9A1vGAKNpdUJzCyT6_vAVrSjUtbdCzrVq6VLjQF5Y73t8507nV-fM4zdAYz8mOLwuOG_1Jb1_plw7gSbXE4nTno9DfUKyoLY-COIcypMbc-wGtNAh1-icNYWTbgQsd4ppXqsDYY7VqJM_UsOR7gHmBJHKnkHKaX2A3ExG0bhmV785xMaz2SURV1G3Z6QrF_HtukifSMvgjQAkgE22pTRYf7LtRxJar5kwMehcBnBvysX-bTMa6AoFRfmc6IWI3fA77cXnLaKx6tuSt9nEVbVffnypJms3Lbg8P0Z66ndUDzKn7BxdcF4bsFwOw-X-Svk2GOoNuM0w5tmqzdNIax6XYscgR92g1MxkeAx56oVlDxna_BswggrJwwa1dnl19abU-WqjkiwrnA9-C6pkZu9ssIYYix6HJaW_oqRz1kzbma_N_y_DAnCsJnMGUosOeqptBqCOgqgR5NItb9QYogNbhssAuZcI-uJ-g8ptJ0Y1YTF2fUFGV9DIv5EHGMAN4SVk_7CMJfJQwhyIjBjz8ml8rJTe_G4FPtEUn3sTBTKkFS-qOYgtwiF33ohcN2gPfGAn-y4YKehcLgwIiPNhYpoy-jdfdEEwfCeAc_e_E4e3ddSE59WV1FWW3XWjutEkf16_oeIfWXwaXa9VEa1ou4BPcxVzny8Cs8Y5BgIsN1zO8rPJYI3rLsiSDQ_4Qohv1fJtCk9gMICX0QRyYFJkHx2CNp4a8pXg4x37B2dKguoEerRFXTtj9sgg4pOcVYxjcA7eq1-y9dfQ0mMRb7t-ilu_ZxjWf1QQGPGd6XCM09icoARZR9VqYbFD80wbOqunwS_3TuRUIKPf17xhDQkLBRhnb5VVUM7b5SBI5d26XhDIXyg4RLREBxRtUQKhWeMTmv8RuoRXhwSfpONa6wlZiy45bsWFfhMTa_VHsYTEFzt1sSlwmxZp8ppiSY33sbjkBH0Bd3DNku9yF2ZBtiYIUkiW9TUPEWg0pwWUSjXYgtFPA2NnWPKe6JiIrrsz1ETWBXnWrZA95ZDBrsoOsLYu5Hhv3Sm3CVcJwe-dBiqgtDdN2tDt2c2Aj41p1zGKQrVUx5BGYdGh5P6ylRfK2wdXtR1i1nc85jNAeqr0oWDDb1mTvHZzSaygU_MsBazE1fzyrT5h8pO4uqRCVmDmsSVVbPUIgQ_XmQnYAw9bZ7rGtP3pzl--f7AVZoDcVR-2WK7p34KGULEwKNW33HGEnUAvSOv5amjDAkFx5LjFbLQy2b4OniBRN3EUlVJa3QkIw5d0dlDUOau40SgMGwIThGGD35F10S8uKXyy1BO37sTkqpr5tqGtIKPmED0B5-VRMT3qd80pW30yM9nn6bckgQRZ1ndoFDjzCzpH5OfxYfKP-9rqDIYTl1pO0f33eKHL_m08BqtHqf8cxS83M1-YUWQOZ-sq_nc9OABElDQTJaKBjDJq8WVq_Ode-tUpisPBCqeNwWFqsCB54tFlyOEJr554LM_qB3s_4CVdcsgbTPTho0IcSX33AOEukxnEZpv6o542HLgljqCHYeUMyBo-fjuEYaH26PVBazqBWFwbdXOZu0oIaoS-lWa2G7LIAkFg8ROLQS8ok4sjdV7ZaunmY3c7Z0IthDuxw_nL_B-6G8oFBj71zTIVSxRDa4ibg_jmRLs75aX-9NNSLe04GJk_ZXMKY2TZj9oTHi0BnmcGDVEEvxU4fy38y56jB4682GuTwwqkRs22d9_vflkWdy0TUj4M-9okr7C4bhMR7Ho3a-NBgLgRJmWwRkutQOKKsIJRwV1EEk9f7QtV902yXveo_wNxTSdCmdDf1nhAnEEf_OdUNbw93V5HF4B79Rwrz7SnoRt0de_ju6tPQtLHRbv_rorgUzSjB2pFQq4QdiuHjhCNN50iv3QX9rwe8NOl8DTqXC82Yx0zVbxRQRCDr0zjHRmB8TXe_yv5gto2WGUTKJpnv9ZvG6IYRTcz2MYNr-LWq3kQ_Lrat1Pxd1pKT5TxCNR6u760N_a5jb650RyVi_i2NjriZRHETAuMjlMPG-ZEiLVHqxk2BDQ4e56H8vWqPqAif2QswyboYektXzrG5FNEf7lyzzUaYBu0ULgdzTCcIeH8SdhvM-MnR_G4HjXrJ90jgNWk-E7LPQ_cWlOr1uZTubOm9FWDav8cMx7SRMntnMNHdeddy3KVnbSAoF0fOZxCc1AV6QAF2U80lPweiDWZ3RkJaX8tCPNvDuQWhqk2RnK2xc8rTu8VRKN9aMwAGqhn-FCzEQ3ic2QDeYkM2lrTkB9Ec98XzO1uSNTr5YsivY3lts7kWC7e6tMrnSjs2WGwhjuFw9gDxYkdH",
            "cfg": {
                "playmod": 1,
                "playcfg": {
                    "pct": [0],
                    "instancerpt": 0,
                    "timingrpt": 0,
                    "92038": 1,
                    "115938": 1,
                    "116392": 1,
                    "116396": 1,
                    "116400": 1,
                    "151043": 1100,
                    "156336": 0,
                    "160561": 64,
                    "160940": 1500,
                    "160966": 660,
                    "161990": 1,
                    "162584": 1,
                    "162864": 1,
                    "162887": 3000,
                    "163290": 1,
                    "163299": 1,
                    "163382": 1,
                    "162285": 1,
                    "162286": 1,
                    "161992": 1,
                    "125372": 1,
                    "155748": 1,
                    "161415": 16,
                    "161406": 1,
                    "161115": 1,
                    "162461": 1,
                    "124878": 1,
                    "160337": 1,
                    "106596": 19,
                    "155625": 1,
                    "121637": 179,
                    "159279": 1,
                    "108674": 2005,
                    "159539": 1,
                    "151276": 1,
                    "159280": 1,
                    "151241": 1,
                    "158955": 1,
                    "120037": 200,
                    "162572": 1,
                    "160035": 1,
                    "156653": 12,
                    "160673": 1,
                    "159788": 1,
                    "159611": 1,
                    "151054": 1,
                    "159116": 1,
                    "156579": 1,
                    "159277": 1,
                    "159056": 1,
                    "158289": 1,
                    "158357": 1,
                    "154785": 40,
                    "158502": 1,
                    "156257": 35,
                    "160210": 1,
                    "159354": 1,
                    "161478": 1,
                    "158823": 1,
                    "162198": 1,
                    "158894": 1,
                    "151496": 1,
                    "120010": 1,
                    "156826": 200,
                    "161737": 1,
                    "159613": 1,
                    "156486": 1,
                    "160641": 0.600000,
                    "151055": 0.150000,
                    "151048": 1.000000,
                    "158935": 0.000000,
                    "116404": "64564400,64564397,64564393,64564389",
                    "121370": 145,
                    "123291": 409,
                    "161879": "Recall,7;Filter,10;Rank,11;Bind,17;Reuse,16",
                    "159964": "4:3",
                    "118118": "1,3,4,5,6,7,8,10",
                    "121780": "op_switch",
                    "158800": "6:1,3",
                    "cimg2hidetime": 10,
                    "displayinterval": 60,
                    "pollcommtime": 60,
                    "displaymode": 1,
                    "poll": "click"
                }
            },
            "ctrl_config": {
                "app": {
                    "acr_cfg": "{\"1\":0,\"2\":4,\"3\":1,\"4\":1,\"n\":6,\"t\":4}",
                    "nusupsak": 1
                }
            },
            "is_encrypted": 1,
            "dr": 0
        }
    }
}


def test():
    d = data.get('data', {})
    r = d.get('9093517612222759', {})
    l = r.get('list', '')
    r = base64.urlsafe_b64decode(l)
    print(r)


if __name__ == '__main__':
    test()

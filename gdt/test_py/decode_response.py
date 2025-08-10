# -*- encoding: utf-8 -*-
# @ModuleName: decode_response
# @Function:
# @Author:
# @Time: 2025/8/7 16:00
import base64
import gzip
import io

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

data = {
	"ret": 0,
	"msg": "",
	"seq": "9951",
	"reqinterval": 1740,
	"last_ads": {
		"responsed_ad_data": "8Q1_qpR5jjA"
	},
	"data": {
		"7022203877744399": {
			"ret": 0,
			"msg": "",
			"list": "W8IBAj4_gVutzWFR-Iq-a-le_vsWhAXxojLkKeLtQurXRIC1KrjtzE_v5ZsmZ5GPteGe1jl3WwY0ZKzdUP6NAx3BH768zIds98s1afDR2BS8ptRglO5Uif0NQVDruo3KB4Ws3z7ztnEzgRe72uNLYIWPDqgFs2Sn-xG1XMBekNCBsuJMtNtxb6rXlWiUkOxUKOM-5-HM2nqahkw1xfUQlepe7nf1MsPj1Lh1YKA4CgvRq-JurmOwO4tEMp6PXgHo5Lz1qobls5xb-rohHAqYqhDL8T3Ezqnp5xnczpYzLPEK4-bBEJ-rI0yolSpJE7OSrZCqIHvww9mLVLmcCwr1MJsmr1FqbDVOaec6Xsin2SQxJoMyiI4-eJ7c27iMV0MpFdwFYFCipWjNUCI0n9K646rNTvA_nVaxW4bVbot0H5uxAgl3jKMyOvo-mjnUFMhXdnvS7N3qH4p-0D5GqZRxWeCsgb-UXIPHGpao5LM7Ru18KZf-ykJDf644ShIaKXb7rFRtQSBxzorXN9NXqUFEomf-gog7ZT_UU27HmbsS4WBD88EoR17_A9cGcdi58YcFyw6UmCXrdvH7G63X6XIrpn7yncToC3_KonzEkSE8hR_22UhfhcMFws44LaTTd_ylKKopACXU2vPg5G5vo7UWab_XCBqd8SRe3Jvx1xHIcwixUZwN8rHZiK0XW5LGcB1bYKSnz6qfiU5_vfGmS7JY20VoM_4ixJyJiQG-64-0zj4jR5op8uVy4X2iFYReVIg9JjRzz-fQ0PltT3TdcUUghAK0BQ2Wo3RRljUvMTIDV4KMHemLrCUQbQVQSCzfocONj3RGGFu9PlEL3r84icT6AdJ_YVf1o-27b2n0_aUOjpzwK3HqjtiH6Z5_MyP316BHXsj4bepe-W0whYRxEYbuHKY_QlRf7iiXifxnsdVgbdVsMIGSQ3pJ_4SNadn4e5jqycCtYXKHsiwSrDslsxFnBZ14CXz3Vohfer5P2Pwvyv3MPWESYA6YcxaF6nbiltgXKqZ1BhEZ63KGPR0Kss_XYHP0qlDuFFkwWugViUiBWiWLZMmkI5YYUm6y6VUoWC3aOiVhPp076CGBGHYFzVuOyB5pU8LIMaPWD0P0YyodEDheFJCtausQvKY-Vu2s7LJEwZyagCUszkyOkBemR4nokI0ZyRJt5KWkblAOlopW60ukHOhy0ZkgWfA_9VZ_WLIK0G9XZiWDC7kVLGLjAJxTm_tIunnB0X2RnutTRkJG5yPxQPJdhfOgqeToNaE5Rie0t7JY5M58FwNzcZkUK8s2RPpKKD7EohLFoT9o0MoUNR_U6daqMMM6Ic7zgIdkmkHRB84FFYXGQqJWS11VF1dHNsX7Dn3PQd4wqZSrjOYwAkniQow9JrPBWAYxTkIL_HekMDf_pYC7JN0PkSJVQ-DMg74Db3RzlVgBJsmEEYOmCdTd-MMtoNuJAQ7HX8ZPWPg-aWYx1Byod7ruXmxGbQDXBhN34V-6ogUC6VCWGVaach-kSsdKleUQ9KmsnO_kyjGGz2pR5hVDTUBc17j0KoAMjuHZ3xW_vgEu4IXLmaKh1IClzyxBwGASLg0LkmcMqQGWMUfx9CA1g8_BV7k0e2YtUG7i6FNYUoQHJQK4cvG1w4-pOufDmiLYvFQaMsCqDjLLHoDaRPGkwSJ8wiq8jSAayOVBUYjakuF12nn-HMHSRB8CF01DVs9IOeE6cJL_qaaBz34tS9uwGqBBz-IrtnmneRzDuizrlmo3dnVyWyBCvjz5Ve2M4Q-yM-PpeLiSQDn3zOpg9cJSBVtXKzKR7E0TzhcGbOyahPlEzCN64zkqmJsOETxzGSSSJ0ESYetoc1qgx8frye5Enewn0ontZQ2AoNUasIvzzOkydGap5loMa7yjxzD6TRwBUz1WBORgZXdfcmOARsGd-VJDYq8qggfmauQtvTOIdFrT9tfixO97llsFm5So-nc25-xR_JEygJt9zKralw2aJBrs5M6IxhJ_zRmIpojsVxVP2mtlEJg-m6N0ULsZhW2_fqr1z1UtuANMgUOgr_2XuF8O51lfj04r_sgiEyzlILdh-Ew94KAtbgMTvsrlE6rCt4ePOkcdfFVvsw182HSbQtE5qqk_Z3UoXn0O3CrC54jFDFwodhk3xZWwp1JRMXFZzsT8QblfdqzxRHxaOE_2QUdgY8QZTH1-6yxII9r-jwkY2MiPwaulH_9XbO3Ek6_syXCHRT4vVN_U368N0bUful05UCiBr0Nfj1ZN5UypvARAN2rALKzqhvcXxvC0cPrjJ1S2HJ0hNgb4RPmRWK9C1m3qtpmt-N5BUnkmoilW_wd3f0xaA90dVWGzPDh8Q6L22YFEddYcdLoAu3BPqjIonQDOsKQBi41hCLP8MDg_pLL4eY7m_vs9uQWE3ycByaQwOltvOns7R07ssJMa7CfLVLDtgtkZqpUgJcpNkF3HSjeRIShuT8LMpTOGFMhvZY1Tz0m8ZyiJZwUlEYKl66VHFjLsbJrA4l9AT8F0I_-n_dzTABsDaa63_dwDmRYAYmGwP-a8tFBeZsWZFwIvWzdCJt0yHE6JqN0X6FMC2dETYohBYMPtBtvq9xRAqdg7b4GXpkjqQbMGYOchnfvX9DxAGzpPxNsCiNOxP82ONftg6GQcoDR5tOeVSPohfpY45B-kfkjQ0cSNcdu66BLbiCyeDRILgVID79XdI_ne44NMTKQt01m9Cy2DZuKHq3FDkqKcGrQoXVWzJtwgBjQ5ncnPswZyrACEOoM7jdlO97OULYaIoGnJam94vpBG7kzAgybnEpGbTsobleUazsfIDG8jHLagQFPPeyt0duisTsioDRu2bOz7y-myJh80eOB2ZSfxAGJxLYB7UDygQqdpQAS4R7FlET5VPYl1dE3WKc-ZQOviCYJ4PCpBEHK79PyDiMVhNH3UXkyS-JuL2jYnE595kUCXaVft8Cx0mS70kw-AGpiuFq2-rrKkQfWJxbqihnklAKvF4g8_dedF04HjAUsTxDQRYxTUGqmBUcGpbL2Q5rtRdD755sjsCWJ9AvmFP591Pv_3fE4QGn55CantVMnjSvjyDVyj4fQH1Iv01m3c7GaQ5KypSFX4UX135gaa7Ae1iHJibexLFtW1uT6g2skobfRoyute11dwTIwCUXusMKxDIMGVMZesL85likhzL3xtTF-L1PZdrA4n0axkxNYC4p-Cni21FySUM3icnsBzP7uzwo5iF4CGR5S2uQCr2AJbeXInNM0d7AOzjiBQz940j8cAxvecc0bsmFBiHBi7tM8WUr_-IiXGhV14jkZYJZayQzhOLquiCNuFgzS1T4yZjrYcKxw8IDr74h7hNBHSWw2_iG8IZ9hU6AdHxkE4S41NGkfJupQA7TQsYxYsw58qXUd3wFNXePR1S0-q1NJI82L7tLJqqROSnMPf7hoU7XXBnE6guabE5s9uN2wvM0-_CSFUFaCuyjl9x6uAQWQbIBEBw0QHEFUUhopHXlUeHJM4LFCXUfm86_XNynFclTroa7bdE-MmjvR5HwIbfEsBsvuNvJBkOcrJSf3pUY4xDr_CB3rsOyFoxAVePmNVPjH2ffiZgpSCPe38QDzlp7E9k8isdKBunFX-dlzseKE7_O7i_tMQ-P9REeaoMEUNhWRFh4tm68x24nSC4MS_6gD42lxpa_9nzAmhpGHSCMAyNnGGNBAAJ5PWwZnA3vkDfDHxeJcLGzI8ptyFW92EUQBOZYly2Jy5H1mcl0dJs3ALuggV0Y7zIUEiysC9i8U80Tbqwl5AdrBM9PSQ6QjgfCrW3ZOFs94O_P7P-J7dRLXtkXk1ndOmqVAysZHzRG6dkN6pUbq7G4AicuBtVEJrsNYvryUUH67vPYrDTMSe3ufy8RS5c-g8pyo-6TQKbDfSPdlAI_nqTQkhE1cNnn4TIY5XG4dtdvE3XyW07kqtd6jmOf8IHlI5gaaegKHNExSlWIBB-joYLUuCbYJ5O2u4o3La0-ugNsULMP_hcvmHpgjS-z8k0oNHlvQjb1JAEgU0sPEQT4lW67Im0izqyI28pgesIhFookKXZLoQ7AFV-Lt9MWD8IyRA9AkwwKaslzvWBS0DOihjkk-2m6X6eHlhqZuXCBF1lJnoIqS890VFVyUzvPZvXJVV15r3AE3ZzH4X8AGS8zUBkw2ZF1yPuQvpieJaYnncmby0txR6BQr7j7Qdr6bDqhDLRIF34v0JRj9DZwGpC1q2WpaYROsG2c_PQIAt6h5a8DBWguGxumllbiOLlEsaaodEi3dzdUwaftN8jiV8cEjCf5vbMFv7lmVaXKsukftqwzxaV5Au5SXhADR5C9HbGhUVyYU1D9a1CJdh9Fjm46Oe-WZ7zqmxztObK3bSW5Im7wrZMfOEqbkTspSZTMznnTA5LyPu9Oc0977XSeEJ2tZCMklpA6XMZi5fU9ZFjU8MB0A4r7ylEDdsVCrjt2y8Trw9LX0RFDPpd1p2cbWfbbvQq5-VUg2-IBJPqIi6fuH0t6t7OnH2QflR1fvn6Zc1jHkreIX4GLJxTlKBIst-b2YCyqRXVx7rv6pJOkNcsXzFA1YM3a2Zi4WoHT-JYpafqr6rgPmECPpV5JrEbNNiu4iNFXwnD7pnbN_yn7MqSD_ymYnLtev6MNRtguP6IuSRV2BeN8gdbIVxml3Bs9qBSCO0XE2MQFaUGSAzgMfo7zdrFRii8EMioiCJ6ASMWLgrLea4REu_IcqWxQ64LypJS3TcbDV83XUDZeyUpTAHdVIE4yl4o314BECy1bQgzhY1jCvuPRzPlZyPlST08G8chGebuskjMwInhtRL6v8_euhf0ARFv66NWnx7PLvZvICLOV_ViyKu03tikQ8cLbp5S50ylcfzRarG4hBU9ouio8UZ9fs5OrmabNW1e50zvoRPC3UZc7L4a08O-StvlPAaBahU56OcAn9CkIQjUNlkTMOQO6rGgiDFIm2pZs38l_BN69vEyumVq4AbrgloxjhGnpt5o9yEf7UDpDZ8ax01tgHff243FwYOd0B4H-68-0W8pMzXM-jaS8VrRntwl4tRGs39DpBi8W4LQ2ID07XG6imTRquGyFhmEcJZE8cLETiQJwBvSOiWTbWkCZyTYb0Fv98qW1DCNJPf6viu8V4QhgTN-kDdzPmy9Cd5bmq-7oFouxLK8v8yIXfDtIoQ0c5nZU7XEPlj2HmZ8qciW6z9fHBkZKPx2H3zsS9BAPslGG1rKiSln5v4lxtlEnxbDRLcJxvk_y1ePKo1aoVc5piXL0yERymypryqdS7j0JR9gwKm0dW5JXZkwtgFREfB3qMoRLXpaO4dAtoLFL0oeqRgbldfTqzkLS4mow3Z1W1LtNxbPHHgpj-K4Vzv-ll1y5clbBCql9Z-GwaEKCL2t6uuHVahF3iAoPHuKL3DyLrnP0HyihNLn9rs3e59s5btNqUnyY9X7XKDgBcEKkBmhiCbCTfaGjrs3KRH0_Nx7YoKhsoHBQAVMDK80RfveM0i4l0Mh5SZgax1BFTutdeS-V8LrSxVJCGxebS27uQKztNqZURfwN1dDYDPyNy3fmaJEX7buxw_o8iBM3C4XqbpjtEkP92ZYdKOT5SW5O47jSg4gqLpDXsUnEpppAh9txrD5FrksdNsJElsfRrzD3p-zSJaeiLr4PGdyoKkT_nti4-12MxKLuwKpG87dTX3KBVr7QUyaNurtXn9oOCHxRH6qLq_ciozhH4Kh_Hp9kmpxZJBEhrVOVIm_ff3IMRRuM8pLquzYCt2xF6TpPUdcShtvJ_9nX4PTWMpcGevzn0e81mVrtfZzW_7d0sn_8URLgg-_JU36AiewGbIPmNy86DMoxzPHpQaJQsLDju2B9AuA3lxTdLWYuU5XS7tpKxR4k-AseWPdG_Go_KP8Q7X_tEB1aLmybyC6zPHSvnk2-A5dCJwQoWAcwwDa9mdEPTJMOwVjNI4VQkMokupbPYruXgye8c6sSCrOozD-h8H-ZV7HMPwc5WnfUVa-Zmj9e29OgDtOZ6zcvn4dBKOY6RLAttYTHx7MH2AYSksxRxcPflaH4Ihm-ckjLyRhk80BVeuR2BWcPlLUdfmpK6SlXX-38j0hwkr1xxgBPXGhgJVj4WTBBL5BpqjXICamRxido6GQ4ct_3tLTGzC39t-hJJhBngF8od1uXnv4wEl75q8Lxqx0BrY7sW2OkI_vd7jEpEoNKljYF-Rjwf95OOa2xpf-LVfGpKOvrYpgAavg-ipd4Z8fh2uFmPw9xzwsj4FUl1YNVS-Mpxb7t0tLZosyNtvN1f8DtsZEFNZvxGS15kdNUboOAz01H9VFcKw6rbZJO1eUPILM58zjYwARG8Bgfk-TWcp0Wg8zIIkE4tqjHc4NbbPjLt0uDVx0Wz0WOXwYWwwu2vpHw0yVr4_AtKadVG3sDuwBzondyUqb0pBF_9Owk_nGF06VdDB9tkrqCOYdhKMkkxMErxdfeYi5wKenYViyUDpTvuOVNEgHqCEC3c9VAJnw5xVuTMuXvT2zKOgGqjbL4nTXg6waP4Drw61twbwI7HpiceGAFTEGPcmZ1rc81v_AU3azw7JkajyhvszsQZK0rqmIDRWGZSyFSofy9UxE5tMmXuv89i8UaRJ3tnfUn8olkFXwCZJEUvpfoU5mZtRi1LKxeDupCuQp1LyXMw-5s6tWle59DiGASquaCcUS1Pdg7vVzL7Ah3xf7zwBAatgqqDFFteT3qN4imsGZ3MeTB6jGafpRNMqZFPdSjHe1dfAHbtROReIxXOaJ_EvtO0nZUzAwQcicAhgV9147JdgW2E265D9Opygb6YkTXpOm16nyMO5eOVCIEHvuohxnAtRwqqn0k22-uF2vA51MWu1z_--yL9Qpc0Dkhjebe5vrCY-IPOJsrgcBIqFC4_0lzjkhsV_6OfSJPyY4QS4SkSQVyrdg2U9ukjv1fn499XuUUrTpS1wPXOFq6VCL01f_fUPzXHpdgrn28iWWEu2zC7JQjEAlVugvZSZn3_wmjRXLseMIRvVcf2GqR6d1--8Pnix8GBo3FiNqjsY0GeTKt_NjVCT2I1Hk80nLDAnrjIVdRIzXJ46NST_96fk8m1vTMeu4depUhyG6uWbL9Ox7yBjdhjOelPqc-XbQdl3jAOjWAcjEt_51jOaXejz8YGWit-CVH0_Ov3gm5DsCmhamEhU3D6zCIqBFrmFo80dbaHdqhyDh-3gIQHY3tcqfJ5BmIwP3vcSx64AaroLveUnanQajDbGC5k7WnGfvF6KSsTGTydrCS5PvCNFcrid3PYfJWFdUqcI5q2E5oZ6MpfmBswtjVh9FEx-pBCTCCmxmFUHAL9IJ_dlELe-YrJc6sJXBYhlbFEgE_F89s165N9JglLuaUP0XzVSYE-xoAOZoLCHY-MB_pXUyzD0Whw6NvveZPhWXC4O74OHnqhZVd5ZXfs1F7TyFrFXFM9sapkTh7tQodwEqfBVQSmU4cGfgdaq5hzixT-J60rwF_Cg_NhA5wKDC0QBwNynGcUsGX0ZM9O7klk5BUa9REH6pPfwEy7R2J9q4HSaUBtgWDT-PcZLd_TBRJ4J29EdTBLSpHIB4juS0aog0McTujXuMrKDXvsdTA2S673QV38WFY1M3o2b1eqR-1l4RdnJ-zU9y3C1rv67QCsqVNci98VPOmVHaGO8HoVIHgFm3uw--_-RZ2icK4NItSkRW5r3cOur56pkzQ47KCY-EIplqVuYGMbjQXOwRX8GN_VYfe92in55PASvt84zRLQtDRbR0Jhu-HN-CN3TNaOADrrvSHME6AkT-2goNaK3CdEmWDewt8Zz0Qp6AQs0ze502g9kz_GV9woOfDA1sOzvD3JurUB4THhZBCqqa-3RPyT1UEM3Rbkg1YLYEw2kkKVBhddAS8WIIxm0q-5024POadMPyx6osRfUZfoglXfajcc3fSkDw0kncx91o0qZD4cgOYCGVJHNufzKh-vRZPihqjN0NiZvi5MaRnp2fclR5ASPDktq3ZGTlt5PD-MfKgdQHSQSfH9sgCXKywLHNcTlUz9urbYbcIle9l6DfgpZJ5-1J9p6YD3Qrt8yTg432JId1L4aAfz__MWBjHhSDbfdFxgbi_hXtXmbOL6dDEd3YbxZRjce-QwsKLJPtMsWS_LjibGxHh4qBQCGz5Zfd_9xlq4AmyeDVIqCz_desw-3LuoClCbcyQ7S7Ek7aZfcQoShSa51zuhizaBwb9wt1GORLTUHaGMlNmJywXosLAeJjHsEXokaMf3fsoT0yE9mcZzoZ1j5VgsVNljLJ9it9B95XZpMIqQv7pqvGa8TlZYxzo2J7ppzi1Y23acNDlkH-1xhGkBoYwtdpnJaxOGwi36STSP9YXm2TP7l1Fp9KRTUmIoRPoG3pFG_JiIGqWqILtVfqWs-8C7hI4vEZZqlVI8y7YOdQKSzfapDg10_k9bS6oPKQQnVas1kXtb1eSlZUr1Jr8ECBCOkwH1Xahnml0S-ffaHdsw1cu2aUnG7h3_vYEFVblmu40y0e2rn8FbvV5mgSXxh3lHOhDJJOG9f3mp9KbBgixqHGwuF0E8ZO_XhCFRjGf9zVD6s7EEwvN65svZsohYa5-e7gS-WPsviCVU6kBDhxfhhqK9lJ8Beazve7AAVlA",
			"cfg": {
				"playmod": 1,
				"playcfg": {
					"pct": [1],
					"instancerpt": 0,
					"timingrpt": 0,
					"92038": 1,
					"115938": 1,
					"116392": 1,
					"116396": 0,
					"116400": 1,
					"151043": 1100,
					"152150": 0,
					"152871": 0,
					"154225": 1,
					"156062": 1,
					"160940": 1500,
					"160966": 660,
					"161990": 1,
					"162864": 1,
					"162887": 3000,
					"163110": 1,
					"163382": 1,
					"163455": 1,
					"162285": 1,
					"163290": 1,
					"161992": 1,
					"155748": 1,
					"161415": 16,
					"161406": 1,
					"161115": 1,
					"162461": 1,
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
					"162286": 1,
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
					"163377": 0.600000,
					"163378": 1.000000,
					"160641": 0.600000,
					"151055": 0.150000,
					"151048": 1.000000,
					"158935": 0.000000,
					"116404": "64564400,64564397,64564393,64564389",
					"121370": 195,
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
				},
				"placement": {
					"delimit_9": 5,
					"dnbtime_9": 2000,
					"lbtime_9": 5000,
					"sptime_9": 20000,
					"vatime_9": "20:00-22:31",
					"vbufferAdType_9": 1
				}
			},
			"is_encrypted": 1,
			"dr": 0
		}
	}
}


def aes_ecb_decrypt(key: bytes, data: bytes, block_size: int = 16) -> bytes:
    """AES/ECB/PKCS7Padding 解密"""
    cipher = AES.new(key, AES.MODE_ECB)
    a = cipher.decrypt(data)
    return unpad(a, block_size)


def decompress_bytes(gzipped_bytes):
    with gzip.GzipFile(fileobj=io.BytesIO(gzipped_bytes)) as f:
        return f.read()


def base64_with_padding(b64_str):
    # 去掉可能的换行符和空格
    b64_str = b64_str.strip().replace("\n", "").replace(" ", "")
    # 计算缺几个 `=`
    padding_needed = len(b64_str) % 4
    if padding_needed:
        b64_str += "=" * (4 - padding_needed)
    return b64_str


def a():
    d = data.get('data', {})
    r = d.get('7022203877744399', {})
    l = r.get('list', '')
    l = base64_with_padding(l)
    r = base64.urlsafe_b64decode(l)

    key = bytes.fromhex(
        'e0cdcfa540b856ed6e329f98d0cc5dfaf7dceafe2080900835f813947ef8a62b')  # 16字节=AES-128；24/32字节可做 AES-192/256

    pt = aes_ecb_decrypt(key, r[4:])
    decompressed = decompress_bytes(pt)
    print(decompressed.decode())

    # print("cipher (hex):", ct.hex())


if __name__ == '__main__':
    a()

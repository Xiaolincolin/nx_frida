# -*- encoding: utf-8 -*-
# @ModuleName: test_new_version
# @Function:
# @Author:
# @Time: 2025/6/11 10:56
import json

import requests


class GDTAdRequest:
    def __init__(self):
        pass

    @staticmethod
    def get_headers():
        headers = {
            'User-Agent': 'GDTMobSDK4.640.1510-[Dalvik/2.1.0 (Linux; U; Android 12; Pixel 4 Build/SQ3A.220705.003.A1)]',
            'Host': 'v2mi.gdt.qq.com',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        return headers

    @staticmethod
    def get_ext():
        ext_data = {
            "req": {
                "m1": "",
                "m3": "06aa5f1134b112ceac954b3b055bf96f",
                "m11": "0101869F3B90511A49DE7D029ED213E34EB4F9F077C20F98BC5305BCD210D236F57B2DEC4FE441C61F00A1A0",
                "m10": "",
                "m9": "vf4FPDVnofsxBOHOPkKD6O7P-538JT2AG0iwdJKi2XZzi6iWVtiAAVqfvWn-6-cT",
                "placement_type": 10,
                "render_type": 1,
                "m12": "00221bc0dda942b8da4fe18b2deca4628a71960a57bb5bcd",
                "posrn": 2,
                "conn": 1,
                "carrier": 0,
                "support_features": 468342509,
                "support_tpl2": 2,
                "tpl_ids": [{
                    "id": "1001588",
                    "ver": 7
                }, {
                    "id": "1001587",
                    "ver": 7
                }, {
                    "id": "1001732",
                    "ver": 0
                }, {
                    "id": "1002365",
                    "ver": 6
                }, {
                    "id": "1002364",
                    "ver": 5
                }, {
                    "id": "1002250",
                    "ver": 2
                }],
                "support_reward_page": 1,
                "support_app_landing_page": 0,
                "c_os": "android",
                "c_osver": "12",
                "c_pkgname": "com.qq.e.union.demo.union",
                "hostver": "4.640.1510.219",
                "c_device": "Pixel 4",
                "c_devicetype": 1,
                "c_mf": "Google",
                "c_ori": 0,
                "c_w": 1080,
                "c_h": 2280,
                "sdkver": "4.640.1510",
                "tmpallpt": True,
                "postype": 11,
                "deep_link_version": 1,
                "c_sdfree": 49708212224,
                "c_market": "",
                "c_hl": "zh",
                "scs": "0001da73bdf2",
                "ast": {
                    "br": "google",
                    "de": "flame",
                    "fp": "google\\/flame\\/flame:12\\/SQ3A.220705.003.A1\\/8672226:user\\/release-keys",
                    "hw": "flame",
                    "pr": "flame",
                    "is_d": False
                },
                "from_js": 0,
                "sdk_st": 1,
                "sdk_cnl": 101,
                "prld": 0,
                "wx_api_ver": 0,
                "opensdk_ver": 638058496,
                "target_ver": 35,
                "query_all_packages": True,
                "support_c2s": 2,
                "support_component": "1,2,3",
                "m_ch": 1,
                "support_app_store": 1,
                "s_hd": 1,
                "appid": "1101152570",
                "harmony_sys_info": {
                    "is_harmony_os": False,
                    "os_version": "",
                    "harmony_pure_mode": -1
                },
                "pms_istl_pkg": 2,
                "ail": {
                    "1": 0,
                    "2": 0,
                    "3": 0,
                    "4": 0,
                    "5": 0,
                    "6": 0
                },
                "ail2": {
                    "v": "1",
                    "l": ["256", "0"]
                },
                "c_release": "12",
                "c_codename": "REL",
                "c_buildid": "SQ3A.220705.003.A1",
                "c_chrover": "95.0.4638.74",
                "c_sw_size": "1",
                "aprn": 5,
                "adrn": 2
            }
        }
        return json.dumps(ext_data, separators=(',', ':'))

    def get_data(self):
        data = {
            'ext': self.get_ext(),
            'posid': '4155726394505156',
            'r': '0.04304497265801199',
            'dev_ext': '{"custom_key":"reward_video"}',
            'adposcount': '1',
            'datatype': '2',
            'support_https': '1',
            'count': '1',
            'mu_p': 'YeMCAczsSGgAAAAAZDQxZDhjZDk4ZjAwYjIwNGU5ODAwOTk4ZWNmODQyN2Uq5JcB4DSG1LfdS_5uJ86_d08606ekc8WgY2iSYzxjnph0vNwpbS60OfGYTMVQX7waJ3Xy8UZvLuzxgUEx9RXkBuJFUQjA82Y6b2LWCBWTmLck1iQ8VHrwQIYXXWCI3e1URgBuev_Stfuydbm9w9fcEUqBCgY7Y4YPge8NUlLWZZ0yJI7XXRVD681jGUx2TROLv0Qxam7XG0pxuoky3dSFsmIiOp9fpBTKKQ0yy0FD3n7L77vVyCapmDj36PvWHB-0WgdfqbBI6gXNuxu11gbbwDWu6GLonaOO3bwoqRV8OAaGQlSTLAudoF2JW_PkRzLMex_mxNIq0LQBUvURkNf0KdKi9QGYNvcdqtx-XWqX10hWcF233y8ZTn-ulw_s2PKH4dz6tBWK42FJey5GiDuY',
            'fc': '1',
        }
        return data

    def main(self):
        headers = self.get_headers()
        data = self.get_data()
        response = requests.post('https://v2mi.gdt.qq.com/gdt_mview.fcg', headers=headers, data=data)
        print(response.json())


if __name__ == '__main__':
    GDTAdRequest().main()

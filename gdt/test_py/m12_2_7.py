# -*- encoding: utf-8 -*-
# @ModuleName: m12_2_7
# @Function:
# @Author:
# @Time: 2025/7/23 10:13

from gdt.py.modify_sha256 import modify_sha256


def get_2_7(data):
    data_1 = data.get('1', {}) or {}
    data_2 = data.get('2', {}) or {}
    data_1_4 = data_1.get('4', '')
    data_1_5 = data_1.get('5', '')
    data_1_6 = data_1.get('6', '')
    data_1_7 = data_1.get('7', '')
    data_1_8 = data_1.get('8', '')
    data_2_5 = data_2.get('5', '')
    str_join = f'{data_2_5}{data_1_7}{data_1_8}{data_1_4}{data_1_5}{data_1_6}'
    even_chars = str_join[::2]
    even_chars = f'pzotrcm869{even_chars}'
    odd_chars = str_join[1::2]
    odd_chars = f'{odd_chars}pzotrcm869'
    index_sha_256_hex = modify_sha256(even_chars)
    value_sha_256_hex = modify_sha256(odd_chars)
    index_sha_256_bytes = bytes.fromhex(index_sha_256_hex)
    value_sha_256_bytes = bytes.fromhex(value_sha_256_hex)
    m12_2_7 = ''
    for item in index_sha_256_bytes:
        index = item & 0x1f
        value_bytes = value_sha_256_bytes[index]
        value = f"{value_bytes:02x}"
        m12_2_7 += value
    return m12_2_7


if __name__ == '__main__':
    d = {
        "1": {
            "1": 1,
            "2": "1753238673409a7e2c4409a3bd329",
            "3": 0,
            "4": "0AND05YQXE52BNH0",
            "5": "2.1.2.17",
            "6": "4.640.1510.219",
            "7": "Android 12,level 32",
            "8": "Pixel 4",
            "9": {},
            "10": {},
            "11": "com.qq.e.union.demo.union",
            "12": "wifi",
            "13": 3
        },
        "2": {
            "1": {},
            "2": "35",
            "3": "{\"QmUin\":\"1753238673409a7e2c4409a3bd329\"}",
            "4": "google",
            "5": "k1:2025-06-06173101.558333356+0800;k2:2025-06-06173128.228336013+0800;k3:0000000000000000;k4:8a196b9a3e36b6db;k5:13106683;k6:12786688;k7:215040;k8:2800;k9:189ca9e5-059c-4e76-afad-42be5509ba28;k11:171;k12:4;k13:2025-06-06173128.228336013+0800;k14:2025-06-26153944.322408685+0800;k15:2954;k16:16;k17:2025-07-23104432.616819287+0800;k18:2025-07-23104432.616819287+0800;k19:853579;k20:4;k21:2025-07-23104432.616819287+0800;k22:2025-07-23104432.616819287+0800;k23:853580;k24:2;k25:2025-07-21150638.285471845+0800;k26:1970-02-26064343.743333955+0800;k27:22982;k28:15;k29:;k30:;k31:;k32:;k33:2025-06-06173128.785002735+0800;k34:2025-07-18105946.665782298+0800;k35:3773;k36:19;k37:2025-06-06173128.785002735+0800;k38:2025-06-06173128.785002735+0800;k39:3772;k40:5;k41:;k42:;k43:;k44:;k45:2025-06-06173123.808335573+0800;k46:2604;k47:2025-06-06173101.478333348+0800;k48:2025-06-06173103.768333576+0800;k49:2025-06-06173123.865002245+0800;k50:2606;k51:;k52:;k53:;k54:2025-06-06173101.478333348+0800;k55:99;k56:2593;k57:2605;k58:2025-06-06173113.881667917+0800;k59:2025-06-06173113.881667917+0800;k60:1990;k61:5582;k62:2025-06-06173124.188335610+0800;k63:2627;k64:2025-06-06173123.511668876+0800;k65:2599;k66:171;k67:2025-06-06173106.721667204+0800;k68:382;k69:;k70:113;k71:2025-06-06173101.478333348+0800;k72:114;k73:2025-06-06173101.481666682+0800;k74:2025-06-06173106.821667214+0800;k75:;k10:1",
            "6": {},
            "7": "fdfdcd9c07e9bfcb9721e9d3cd2c2cc41ccd812c07b3ba2cf183c41cd32197cb",
            "8": {},
            "9": {},
            "10": {},
            "11": {},
            "12": "{\"harmony\":\"0\",\"clone\":\"0\",\"containe\":\"\",\"oz\":\"ZyjSxsx+BaNjy+w4fD1MC+4h9HkvETw+\\/QhmVTHoSR0=\",\"oz2\":\"\",\"oo\":\"7FszTxhlP42TZPpH1M2Eyg==\",\"kelong\":\"0\",\"ip\":\"192.168.100.116\",\"multiUser\":\"0\",\"bod\":\"flame\",\"brd\":\"google\",\"dv\":\"flame\",\"firstLevel\":\"29\",\"manufact\":\"Google\",\"name\":\"flame\",\"host\":\"abfarm848\",\"kernel\":\"Linux localhost 4.14.261-gdbc92b7a2b83-ab8577204 #1 SMP PREEMPT Thu May 12 09:07:20 UTC 2022 aarch64\",\"pre\":\"0\",\"av\":\"4.640.1510.219\",\"ch\":\"\",\"svr\":\"\",\"fit\":1749609461905,\"jv\":\"2.1.2.17\"}",
            "13": {},
            "14": "Phone",
            "15": "1753063271",
            "16": {},
            "18": "mND19C5x+Qfpjc8lKBpgx94cSsf3lGCEU9RprGgpcvrjBfejdcJ0C9zj8fnI3PodDEb1vtGc4zse8K6/q3lJPNVMgT54Rl9tOfO51ZTxxFQnwt4ATT4Eb/shkpxyxMHLjPE/fWrW0PcFYtFT79OcPVVJWiqZUYJaoypVsGSlVJBpMruEt/PZAHeKLElrfv8nbXGTnr1G58mpQh9vIkuURT4ah9LzfrY4EpCLxzxe6m1IzajDVyDulEWaAZggg+ZM1+GkMVqN6G/rBK2zj7WhDg=="
        }
    }
    get_2_7(d)

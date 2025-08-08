# -*- encoding: utf-8 -*-
# @ModuleName: mm_hash
# @Function:
# @Author:
# @Time: 2025/8/6 11:49
def get_ts_seed(ts, round_times=15):
    ts_seed = ''
    for _ in range(round_times):
        seed = (214013 * ts + 2531011) & 0xFFFFFFFF  # emulate 32-bit wraparound
        tmp = seed >> 16
        v75 = (tmp ^ 0xFFFFFFFF8000) & tmp
        ts = v75
        ts_seed += str(hex(v75))[2:]
    return ts_seed


def mm_hash(a1: bytes, a2: int, a3: int) -> int:
    def mask64(x):
        return x & 0xFFFFFFFFFFFFFFFF

    CONST = 0xC6A4A7935BD1E995
    MASK1 = 0x1DD238910B954391
    MASK2 = 0xE22DC76EF46ABC6E

    v3 = mask64(CONST * a2)
    v4 = ~v3 & MASK1
    v5 = v3 & MASK2

    v6 = a2 if a2 >= 0 else a2 + 7
    v7 = (v4 | v5) ^ ((~a3 & MASK1) | (a3 & 0xF46ABC6E))

    a1_pos = 0
    if (v6 >> 3) * 8:
        v8 = v6 >> 3
        v10 = 8 * v8
        while v10:
            if a1_pos + 8 > len(a1):
                break
            v11 = int.from_bytes(a1[a1_pos:a1_pos + 8], "little")
            a1_pos += 8
            v10 -= 8
            mul = mask64(CONST * v11)
            v12 = mask64(CONST * (((~(mul >> 47)) & 0x4CD856B83008188C | ((mul >> 47) & 0xB327A947CFF7E773)) ^
                                  ((~mul & 0x4CD856B83008188C) | (mul & 0xB327A947CFF7E773))))
            v7 = mask64(CONST * ((v7 & ~v12) | (v12 & ~v7)))
    v9 = a1[a1_pos:]
    remainder = (a2 ^ 0xFFFFFFF8) & a2
    if remainder >= 1:
        if remainder == 7:
            v7 = ~v7 & (v9[6] << 48) | v7 & ~(v9[6] << 48)
        if remainder >= 6:
            v7 = v7 & ~(v9[5] << 40) | ~v7 & (v9[5] << 40)
        if remainder >= 5:
            v7 = (~(v9[4] << 32) & 0x45682298A6135C18 | (v9[4] << 32) & 0xBA97DD6759ECA3E7) ^ (
                    (~v7 & 0x45682298A6135C18) | (v7 & 0xBA97DD6759ECA3E7))
        if remainder >= 4:
            v7 = (~(v9[3] << 24) & 0x32930CFAEBFC669 | (v9[3] << 24) & 0x51403996) ^ (
                    (~v7 & 0x32930CFAEBFC669) | (v7 & 0xFCD6CF3051403996))
        if remainder >= 3:
            v7 = ~v7 & (v9[2] << 16) | v7 & ~(v9[2] << 16)
        if remainder >= 2:
            v7 = (~(v9[1] << 8) & 0xF54DEDF489DF44C5 | (v9[1] << 8) & 0xBB3A) ^ (
                    (~v7 & 0xF54DEDF489DF44C5) | (v7 & 0xAB2120B7620BB3A))
        if remainder >= 1:
            v7 = mask64(CONST * ((v9[0] & ~v7) | (v7 & ~v9[0])))

    v13 = mask64(CONST * (((~(v7 >> 47)) & 0x3C05A1DAD3B8D91B | ((v7 >> 47) & 0xC3FA5E252C4726E4)) ^
                          ((~v7 & 0x3C05A1DAD3B8D91B) | (v7 & 0xC3FA5E252C4726E4))))
    return mask64(v13 & ~(v13 >> 47) | ~v13 & (v13 >> 47))


def get_map_1():
    data = {
        "21": "0",
        "108": "0",
        "7": "",
        "10": "112221.98,112221.98",
        "105": "79",
        "14": "1440*2984",
        "101": "0",
        "152": "0",
        "103": "0",
        "104": "1",
        "33": "32",
        "11": "type=1:name=LSM6DSR Accelerometer:vendor=STMicro:resolution=0.0047856453:,type=2:name=LIS2MDL Magnetometer:vendor=STMicro:resolution=0.01:,type=4:name=LSM6DSR Gyroscope:vendor=STMicro:resolution=0.0012216945:,type=5:name=TMD3702V Ambient Light Sensor:vendor=AMS:resolution=0.01:,type=6:name=BMP380 Pressure Sensor:vendor=Bosch:resolution=0.0017:,",
        "24": "Pixel 4 XL",
        "12": "QualcommTechnologies,IncSM8150",
        "23": "google",
        "8": "google/coral/coral:12/S3B1.220218.004/8242181:user/release-keys",
        "13": "3700.0",
        "25": "12",
        "20": "4",
        "100": "",
        "22": "",
        "28": "01019C1AFD79568C66C977930AB8450604ED26C55116EA7C78D35D229974E259D9F7E3F82E6C6EC03BA5C055",
        "102": "0",
        "106": "",
        "115": "",
        "113": "0",
        "44": "",
        "35": "",
        "42": "Google",
        "17": "",
        "107": "com.qq.e.union.demo.union_812EDD5567C5D1DADDACB9D0522567C1",
        "47": "",
        "49": "",
        "48": "dc1ddac14c487609",
        "200": "32,2,3,4,36,5,6,40,136,43,143,144,10002,114,19,10003,99905728",
        "116": "",
        "117": "3",
        "119": "unknown",
        "26": "f9315c10fe1348da89626322cc4b17e7",
        "45": "",
        "118": "v4;-1_v6;-1",
        "120": "",
        "121": "",
        "122": "",
        "135": "tmpfs:/dev:tmpfs:rw&seclabel&nosuid&relatime&mode=755,tmpfs:/mnt:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755&gid=1000,/dev/fuse:/mnt/installer/0/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/mnt/installer/0/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,/dev/block/platform/soc/1d84000.ufshc/by-name/persist:/mnt/vendor/persist:ext4:rw&seclabel&nosuid&nodev&noatime&data=ordered,/dev/block/by-name/metadata:/metadata:ext4:rw&seclabel&nosuid&nodev&noatime&discard&nodelalloc&commit=1&data=journal,/dev/block/bootdevice/by-name/modem_b:/vendor/firmware_mnt:vfat:ro&context=u#object_r#firmware_file#s0&relatime&gid=1000&fmask=0337&dmask=0227&codepage=437&iocharset=iso8859-1&shortname=lower&errors=remount-ro,magisk:/debug_ramdisk:tmpfs:rw&seclabel&relatime&mode=755,tmpfs:/apex:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,tmpfs:/apex/apex-info-list.xml:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,magisk:/data/adb/modules/zygisk_shamiko/module.prop:tmpfs:rw&seclabel&relatime&mode=755,tmpfs:/system/etc/security/cacerts:tmpfs:rw&seclabel&relatime,magisk:/system/bin:tmpfs:ro&seclabel&relatime&mode=755,/dev/fuse:/storage/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/storage/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,tmpfs:/data/data:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user_de:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/cur:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/ref:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,/dev/block/loop::17,/dev/block/dm::1213",
        "124": "",
        "125": "7123122431912673932:1:0_19_340024_493_1919,-9212923712877298754:1:0_19_310168_493_22894,8138465491340383747:1:1000_1944_1013048_420_38,2009883582161427382:1:0_5_0_292_98884,-8078172656258477214:1:0_5_0_292_106795",
        "126": "1754300720361",
        "34": "C:1,T:1754300819884,LT:1705",
        "129": "8,wlan0;4163;4;fe80::126:32c0:a730:ed5b;fd0a:a5a2:5da9:0:c007:6f0c:377f:cf2b;fd0a:a5a2:5da9:0:e84b:2c8:cb98:f615;192.168.100.112,r_rmnet_data0;65;1;fe80::cfd3:a9fe:f9ff:1c4c,dummy0;195;1;fe80::dcf0:bdff:fe6f:d578",
        "131": "0,0,内置屏幕,1440x3040,131,1,0,",
        "137": "-336568457738497426:1,7026921823820558012:locked,573726331679131030:green,-8233870966039513836:enforcing,-8268411640757575412:0,-3970424417706690388:1,7247450386580705748:0",
        "133": "android.content.pm.IPackageManager$Stub$Proxy,,",
        "140": "0,0,,0,,",
        "138": "5,1",
        "141": "5596784",
        "146": "2,272496640,wlan0,192.168.100.112;fe80::126:32c0:a730:ed5b;fd0a:a5a2:5da9:0:c007:6f0c:377f:cf2b;fd0a:a5a2:5da9:0:e84b:2c8:cb98:f615,fd0a:a5a2:5da9::1;192.168.100.100",
        "147": "1,-4516327767009073080:7199c760:/system/framework/arm64/boot-framework.oat:FFC302D1F35305A9:r-xp:64773:1178,-4844424437839471813:6f02e00090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1928:108,44102712923359780:6f02e00090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1928:108,4353017571826496965:719f8610:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,-4153032832367424344:70384880:/apex/com.android.art/javalib/arm64/boot.oat:F00B40D11F0240B9:r-xp:1928:63,-5151164676057608033:71cb7a60:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,288159253053431654:71d3f400:/system/framework/arm64/boot-framework.oat:201840FDC0035FD6:r-xp:64773:1178,-2980294074726822096:6f02e00090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1928:108,2559244107516066520:6f02e00090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1928:108,4473348173689220732:71cf3bf0:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,6869870101328312217:70553100:/apex/com.android.art/javalib/arm64/boot.oat:F00B40D11F0240B9:r-xp:1928:63,-3709677853439453148:6f02f1dcb8:/apex/com.android.art/lib64/libart.so:FF8304D1E85B00FD:r-xp:1928:108:183:2b417e2566f5eb686666666b6ee952ea:1928:108:FF8304D1E85B00FD:,7196916155523678026:6f02ed75b0:/apex/com.android.art/lib64/libart.so:FF8303D1E007016D:r-xp:1928:108:183:2b417e2566f5eb686666666b6ee952ea:1928:108:FF8303D1E007016D:,-3379978139409198809:71b0b72c5c:/apex/com.android.runtime/lib64/bionic/libc.so:FFC304D1FD7B0EA9:r-xp:1944:38:183:7d17e80a3a778c83afd706bd6ae4029b:1944:38:FFC304D1FD7B0EA9:,1907461101413668651:71b0bbe758:/apex/com.android.runtime/lib64/bionic/libc.so:FD7BBEA9F30B00F9:r-xp:1944:38:183:7d17e80a3a778c83afd706bd6ae4029b:1944:38:FD7BBEA9F30B00F9:,6233979380418259349:71af2bd310:/system/lib64/libcamera_client.so:266BFF17EA79FF17:r-xp:64773:2058:183:826efdfa62ce3adf1b122c6275effc06:64773:2058:266BFF17EA79FF17:,5658918889255550592:71a4cf1a50:/system/lib64/libgui.so:FF4302D1FD7B04A9:r-xp:64773:2138:183:05ffaa20994aea7f02c7638e52fa75bf:64773:2138:FF4302D1FD7B04A9:,-2494213541457932276:719a523f38:/system/lib64/libandroid_runtime.so:FF0302D1FD7B02A9:r-xp:64773:2005:183:22de26fa7397114f43e2da9279131a0e:64773:2005:FF0302D1FD7B02A9:",
        "149": "zh-CN",
        "150": "Asia/Shanghai",
        "151": "46009"
    }
    key_list = list(data.keys())
    key_int_list = [int(key) for key in key_list]
    key_int_list.sort()
    r = ''
    for key in key_int_list:
        value = data[str(key)]
        if not value:
            continue
        r += value
    return r


def test():
    m11_body_2_ts = 1754300821594
    map_1_params = get_map_1()
    ts_seed = get_ts_seed(m11_body_2_ts, round_times=16)
    print(map_1_params)
    map_1_params += ts_seed
    map_1_params_bytes = map_1_params.encode()
    sign_value = mm_hash(map_1_params_bytes, len(map_1_params_bytes), 0)
    print('sign_value', hex(sign_value))


if __name__ == '__main__':
    test()

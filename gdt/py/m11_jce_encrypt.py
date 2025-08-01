# -*- encoding: utf-8 -*-
# @ModuleName: m11_jce_encrypt
# @Function:
# @Author:
# @Time: 2025/7/30 13:53

from hexdump import hexdump
import zlib
from gdt.jce_struct import types
from gdt.py.m11_jce import DeviceStruct, FirstBody, DevM2Struct, ReqStruct, StringBytesMapStruct, SecondBody, \
    SecondDeviceStruct, SecondDev3, SecondDev4, SecondDev5, SecondReqStruct, ThirdBody, ThirdDeviceStruct, ThirdDev1, \
    ThirdDev3, ThirdDev8, ThirdReqStruct
import struct

XX_TEA_KEY = [
    0xD2785EF1,
    0xC4C23330,
    0x25A9C8BA,
    0x3A867E67
]


class M11JceEncrypt:
    def __init__(self):
        pass

    def decode_response(self, data_bytes: bytes):
        """
        解密响应数据/body
        :param data_bytes:
        :return:
        """
        enc_bytes = self.xx_tea_decrypt(data_bytes)
        un_zlib_bytes = self.decompress_data(enc_bytes)
        hexdump(un_zlib_bytes)

    @staticmethod
    def compress_data(data):
        """压缩数据"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return zlib.compress(data)

    @staticmethod
    def compress_obj(data):
        compressor = zlib.compressobj(
            level=9,  # same as Z_DEFAULT_COMPRESSION
            method=zlib.DEFLATED,
            wbits=15,  # same as deflateInit (zlib header)
            memLevel=8,  # default in zlib
            strategy=zlib.Z_DEFAULT_STRATEGY
        )
        compressed = compressor.compress(data)
        compressed += compressor.flush()
        return compressed

    @staticmethod
    def decompress_data(compressed_data):
        """解压缩数据"""
        return zlib.decompress(compressed_data)

    @staticmethod
    def xx_tea_decrypt(data: bytes) -> bytes:
        key = XX_TEA_KEY
        if len(data) % 4 != 0 or len(data) < 8:
            raise ValueError("Invalid encrypted data length")

        v = list(struct.unpack('<%dI' % (len(data) // 4), data))
        n = len(v)
        delta = 0x9E3779B9  # 注意：这是正确的XXTEA delta值，0x61C88647是其补数
        rounds = 6 + 52 // n
        sum_ = (rounds * delta) & 0xFFFFFFFF

        for _ in range(rounds):
            e = (sum_ >> 2) & 3
            for p in reversed(range(n)):  # 从后向前处理
                if p == 0:
                    z = v[-1]  # 处理第一个元素时，z是最后一个元素
                else:
                    z = v[p - 1]

                y = v[(p + 1) % n]  # 处理边界情况
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))
                v[p] = (v[p] - mx) & 0xFFFFFFFF
            sum_ = (sum_ - delta) & 0xFFFFFFFF  # 解密时delta应该是递减

        # 取原始长度
        orig_len = v[-1]
        decrypted = struct.pack('<%dI' % (n - 1), *v[:-1])
        return decrypted[:orig_len]

    @staticmethod
    def xx_tea_encrypt(input_bytes: bytes) -> bytes:
        # 填充：4字节对齐 + 附加原始长度
        key = XX_TEA_KEY
        n = len(input_bytes)
        pad = (4 - (n % 4)) % 4
        padded = input_bytes + b'\x00' * pad
        padded += struct.pack('<I', n)  # 原始长度追加到末尾
        v = list(struct.unpack('<%dI' % (len(padded) // 4), padded))

        # 加密过程
        delta = 0x61C88647  # -0x3C6EF372
        rounds = 6 + 52 // len(v)
        sum_ = 0
        n = len(v)
        z = v[-1]

        for _ in range(rounds):
            sum_ = (sum_ - delta) & 0xFFFFFFFF
            e = (sum_ >> 2) & 3
            for p in range(n - 1):
                y = v[p + 1]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))
                v[p] = (v[p] + mx) & 0xFFFFFFFF
                z = v[p]
            y = v[0]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (key[((n - 1) & 3) ^ e] ^ z))
            v[-1] = (v[-1] + mx) & 0xFFFFFFFF
            z = v[-1]

        # 输出加密数据
        return struct.pack('<%dI' % n, *v)

    @staticmethod
    def create_first_map2(data: dict):
        keyword_list = [
            'platform', 'version', 'lc', 'channel', 'appid',
            'pkg', 'pkgVerInfo', 'apiLevel', 'brand', 'model'
        ]
        result = {}
        for keyword in keyword_list:
            key = types.STRING(keyword)
            value = data.get(keyword, '') or ''
            value = types.STRING(value)
            result[key] = value
        return result

    def create_first_body(self, device_info: dict):
        ts = device_info.get('first_ts', 0)
        sign = device_info.get('sign', '')

        first_body = FirstBody()
        dev_struct = DeviceStruct()
        dev_struct.int_0 = ts
        dev_struct.map_1 = self.create_first_map2(device_info)
        dm2 = DevM2Struct()
        dm2.field0 = types.ZERO_TAG
        dm2.field1 = 1
        dm2.field2 = types.ZERO_TAG
        dm2.field3 = {}
        dm2.field4 = {}
        dm2.field5 = types.ZERO_TAG
        dev_struct.map_2 = dm2
        dev_struct.str_3 = sign
        req_struct = ReqStruct()
        req_struct.devs = dev_struct
        req_result = req_struct.encode()
        sb = StringBytesMapStruct()
        sb.int_0 = {types.STRING('req'): types.BYTES(req_result)}
        bytes_7_value = sb.encode()
        first_body.int_1 = 3
        first_body.int_2 = 0
        first_body.int_3 = 0
        first_body.int_4 = 3
        first_body.str_5 = 'getTFConfig'
        first_body.str_6 = 'getTFConfig'
        first_body.bytes_7 = bytes_7_value
        r = first_body.encode()
        length = len(r) + 4
        length_hex = f"{length:08x}"
        r = bytes.fromhex(length_hex) + r
        hexdump(r)
        print(len(r))
        return r

    def get_first_body(self, device_info: dict):
        jce_bytes = self.create_first_body(device_info)
        zip_bytes = self.compress_data(jce_bytes)
        body = self.xx_tea_encrypt(zip_bytes)
        hexdump(body)

    @staticmethod
    def device_data_map1():
        data = {
            "47": "",
            "49": "",
            "48": "b1349b36b6571cb0",
            "7": "",
            "8": "google/flame/flame:12/SQ3A.220705.003.A1/8672226:user/release-keys",
            "12": "QualcommTechnologies,IncSM8150",
            "13": "2800.0",
            "9": "/dev/block/dm-5:860160,tmpfs:2798400,tmpfs:2798400,/dev/block/dm-6:289660,magisk:2798400,magisk:2798400,/dev/block/dm-7:798868,/dev/block/dm-8:2390500,",
            "10": "51197.98,51197.98",
            "11": "type=1:name=LSM6DSR Accelerometer:vendor=STMicro:resolution=0.0047856453:,type=2:name=LIS2MDL Magnetometer:vendor=STMicro:resolution=0.01:,type=4:name=LSM6DSR Gyroscope:vendor=STMicro:resolution=0.0012216945:,type=5:name=TMD3702V Ambient Light Sensor:vendor=AMS:resolution=0.01:,type=6:name=BMP380 Pressure Sensor:vendor=Bosch:resolution=0.0017:,",
            "14": "1080*2236",
            "15": "The_big_adventure.ogg",
            "16": "6751f2c1c69a4fe5",
            "17": "1:1:10222:1749439623869:com.topjohnwu.magisk::11801932:app/~~Z6kIfj4zM24IRpX3GavCAA==/-Ow_8jnwFd0ttTF0J2Sc5sw=,1:1:10228:1749609461905:com.qq.e.union.demo.union::23417533:app/~~U3surGAUUL2AUMBQNNpEcg==/-i4wn7CdWFRy9Y_WCpYlhEQ=,",
            "18": "/system/:1230768000:0:14:,/system/apex/:1230768000:0:25:,/system/apex/com.android.runtime.apex:1230768000:8132090:0:,/system/app/:1230768000:0:23:,/system/app/BasicDreams/:1230768000:0:1:,/system/app/BasicDreams/BasicDreams.apk:1230768000:54047:0:,/system/app/Bluetooth/:1230768000:0:2:,/system/app/Bluetooth/Bluetooth.apk:1230768000:3823261:0:,/system/app/Bluetooth/lib/:1230768000:0:0:,/system/app/BluetoothMidiService/:1230768000:0:1:,/system/app/BluetoothMidiService/BluetoothMidiService.apk:1230768000:29142:0:,/system/app/BookmarkProvider/:1230768000:0:1:,/system/app/BookmarkProvider/BookmarkProvider.apk:1230768000:33576:0:,/system/app/CameraExtensionsProxy/:1230768000:0:1:,/system/app/CameraExtensionsProxy/CameraExtensionsProxy.apk:1230768000:37334:0:,/system/app/CaptivePortalLoginGoogle/:1230768000:0:1:,/system/app/CaptivePortalLoginGoogle/CaptivePortalLoginGoogle.apk:1230768000:549093:0:,/system/app/CarrierDefaultApp/:1230768000:0:1:,/system/app/CarrierDefaultApp/CarrierDefaultApp.apk:1230768000:140075:0:,/system/app/CertInstaller/:1230768000:0:1:,/system/app/CertInstaller/CertInstaller.apk:1230768000:549926:0:,/system/app/CompanionDeviceManager/:1230768000:0:1:,/system/app/CompanionDeviceManager/CompanionDeviceManager.apk:1230768000:91027:0:,/system/app/EasterEgg/:1230768000:0:1:,/system/app/EasterEgg/EasterEgg.apk:1230768000:1871274:0:,/system/app/GoogleExtShared/:1230768000:0:1:,/system/app/GoogleExtShared/GoogleExtShared.apk:1230768000:16854:0:,/system/app/GooglePrintRecommendationService/:1230768000:0:1:,/system/app/GooglePrintRecommendationService/GooglePrintRecommendationService.apk:1230768000:94054:0:,/system/app/HTMLViewer/:1230768000:0:1:,/system/app/HTMLViewer/HTMLViewer.apk:1230768000:33372:0:,/system/app/KeyChain/:1230768000:0:2:,/system/app/KeyChain/KeyChain.apk:1230768000:3359061:0:,/system/app/KeyChain/oat/:1230768000:0:0:,/system/app/LiveWallpapersPicker/:1230768000:0:1:,/system/app/LiveWallpapersPicker/LiveWallpapersPicker.apk:1230768000:2801172:0:,/system/app/NfcNci/:1230768000:0:2:,/system/app/NfcNci/NfcNci.apk:1230768000:2098592:0:,/system/app/NfcNci/lib/:1230768000:0:0:,/system/app/PacProcessor/:1230768000:0:1:,/system/app/PacProcessor/PacProcessor.apk:1230768000:20950:0:,/system/app/PartnerBookmarksProvider/:1230768000:0:1:,/system/app/PartnerBookmarksProvider/PartnerBookmarksProvider.apk:1230768000:25046:0:,/system/app/PrintSpooler/:1230768000:0:2:,/system/app/PrintSpooler/PrintSpooler.apk:1230768000:759107:0:,/system/app/PrintSpooler/lib/:1230768000:0:0:,/system/app/SecureElement/:1230768000:0:1:,/system/app/SecureElement/SecureElement.apk:1230768000:86486:0:,/system/app/SimAppDialog/:1230768000:0:1:,/system/app/SimAppDialog/SimAppDialog.apk:1230768000:285924:0:,/system/app/Stk/:1230768000:0:1:,/system/app/Stk/Stk.apk:1230768000:2156620:0:,/system/app/WallpaperBackup/:1230768000:0:2:,/system/app/WallpaperBackup/WallpaperBackup.apk:1230768000:29149:0:,/system/app/WallpaperBackup/oat/:1230768000:0:0:,/system/bin/:1230768000:0:0:,/system/build.prop:1230768000:4159:0:,/system/etc/:1230768000:0:43:,/system/etc/bluetooth/:1230768000:0:2:,/system/etc/bluetooth/bt_stack.conf:1230768000:1952:0:,/system/etc/bpf/:1230768000:0:4:,/system/etc/bpf/time_in_state.o:1230768000:10656:0:,/system/etc/cgroups.json:0:0:0:,/system/etc/classpaths/:1230768000:0:2:,/system/etc/classpaths/systemserverclasspath.pb:1230768000:137:0:,/system/etc/compatconfig/:1230768000:0:5:,/system/etc/compatconfig/services-platform-compat-config.xml:1230768000:21339:0:,/system/etc/fs_config_dirs:1230768000:0:0:,/system/etc/init/:1230768000:0:59:,/system/etc/init/hw/:1230768000:0:0:,/system/etc/init/update_engine.rc:1230768000:323:0:,/system/etc/permissions/:1230768000:0:15:,/system/etc/permissions/privapp-permissions-google.xml:1230768000:7796:0:,/system/etc/ppp/:1230768000:0:1:,/system/etc/ppp/ip-up-vpn:1230768000:11048:0:,/system/etc/res/:1230768000:0:1:,/system/etc/res/images/:1230768000:0:0:,/system/etc/seccomp_policy/:1230768000:0:6:,/system/etc/seccomp_policy/crash_dump.arm.policy:1230768000:534:0:,/system/etc/security/:1230768000:0:4:,/system/etc/security/cacerts/:1753668283:0:0:,/system/etc/security/cacerts_google/:1230768000:0:0:,/system/etc/security/fsverity/:1230768000:0:0:,/system/etc/security/otacerts.zip:1230768000:2268:0:,/system/etc/selinux/:1230768000:0:10:,/system/etc/selinux/mapping/:1230768000:0:0:,/system/etc/selinux/plat_hwservice_contexts:0:0:0:,/system/etc/selinux/plat_sepolicy_and_mapping.sha256:1230768000:65:0:,/system/etc/sysconfig/:1230768000:0:3:,/system/etc/sysconfig/preinstalled-packages-platform.xml:1230768000:5104:0:,/system/etc/task_profiles/:1230768000:0:6:,/system/etc/task_profiles/cgroups_30.json:0:0:0:,/system/etc/task_profiles/task_profiles_28.json:1230768000:2912:0:,/system/etc/vintf/:1230768000:0:7:,/system/etc/vintf/compatibility_matrix.5.xml:1230768000:124106:0:,/system/etc/vintf/manifest/:1230768000:0:0:,/system/fonts/:1230768000:0:207:,/system/fonts/AndroidClock.ttf:1230768000:4540:0:,/system/framework/:1230768000:0:51:,/system/framework/arm/:1230768000:0:21:,/system/framework/arm/boot-ims-common.art:1230768000:77824:0:,/system/framework/arm64/:1230768000:0:21:,/system/framework/arm64/boot-ims-common.art:1230768000:81920:0:,/system/framework/com.android.nfc_extras.jar:1230768000:7986:0:,/system/framework/oat/:1230768000:0:2:,/system/framework/oat/arm/:1230768000:0:0:,/system/framework/oat/arm64/:1230768000:0:0:,/system/lib/:1753668283:0:398:,/system/lib/bootstrap/:0:0:0:,/system/lib/drm/:1753668283:0:1:,/system/lib/drm/libfwdlockengine.so:1230768000:39012:0:,/system/lib/hw/:1753668283:0:3:,/system/lib/hw/audio.hearing_aid.default.so:1230768000:1399676:0:,/system/lib/libzygisk.so:1753668283:220296:0:,/system/lib/spatializer-aidl-cpp.so:1230768000:48020:0:,/system/lib64/:1753668283:0:581:,/system/lib64/bootstrap/:0:0:0:,/system/lib64/drm/:1753668283:0:1:,/system/lib64/drm/libfwdlockengine.so:1230768000:59072:0:,/system/lib64/hw/:1753668283:0:3:,/system/lib64/hw/audio.hearing_aid.default.so:1230768000:1870888:0:,/system/lib64/libzygisk.so:5438826:345880:0:,/system/lib64/spatializer-aidl-cpp.so:1230768000:97688:0:,/system/priv-app/:1230768000:0:37:,/system/priv-app/BackupRestoreConfirmation/:1230768000:0:1:,/system/priv-app/BackupRestoreConfirmation/BackupRestoreConfirmation.apk:1230768000:258676:0:,/system/priv-app/BlockedNumberProvider/:1230768000:0:1:,/system/priv-app/BlockedNumberProvider/BlockedNumberProvider.apk:1230768000:324061:0:,/system/priv-app/BuiltInPrintService/:1230768000:0:2:,/system/priv-app/BuiltInPrintService/BuiltInPrintService.apk:1230768000:542142:0:,/system/priv-app/BuiltInPrintService/lib/:1230768000:0:0:,/system/priv-app/CalendarProvider/:1230768000:0:1:,/system/priv-app/CalendarProvider/CalendarProvider.apk:1230768000:599013:0:,/system/priv-app/CallLogBackup/:1230768000:0:1:,/system/priv-app/CallLogBackup/CallLogBackup.apk:1230768000:33245:0:,/system/priv-app/CellBroadcastLegacyApp/:1230768000:0:1:,/system/priv-app/CellBroadcastLegacyApp/CellBroadcastLegacyApp.apk:1230768000:1490366:0:,/system/priv-app/ContactsProvider/:1230768000:0:1:,/system/priv-app/ContactsProvider/ContactsProvider.apk:1230768000:975407:0:,/system/priv-app/DocumentsUIGoogle/:1230768000:0:1:,/system/priv-app/DocumentsUIGoogle/DocumentsUIGoogle.apk:1230768000:6406235:0:,/system/priv-app/DownloadProvider/:1230768000:0:1:,/system/priv-app/DownloadProvider/DownloadProvider.apk:1230768000:791495:0:,/system/priv-app/DownloadProviderUi/:1230768000:0:1:,/system/priv-app/DownloadProviderUi/DownloadProviderUi.apk:1230768000:267207:0:,/system/priv-app/DynamicSystemInstallationService/:1230768000:0:1:,/system/priv-app/DynamicSystemInstallationService/DynamicSystemInstallationService.apk:1230768000:160314:0:,/system/priv-app/ExternalStorageProvider/:1230768000:0:1:,/system/priv-app/ExternalStorageProvider/ExternalStorageProvider.apk:1230768000:70109:0:,/system/priv-app/FusedLocation/:1230768000:0:2:,/system/priv-app/FusedLocation/FusedLocation.apk:1230768000:41437:0:,/system/priv-app/FusedLocation/oat/:1230768000:0:0:,/system/priv-app/GooglePackageInstaller/:1230768000:0:1:,/system/priv-app/GooglePackageInstaller/GooglePackageInstaller.apk:1230768000:3303378:0:,/system/priv-app/InputDevices/:1230768000:0:2:,/system/priv-app/InputDevices/InputDevices.apk:1230768000:291123:0:,/system/priv-app/InputDevices/oat/:1230768000:0:0:,/system/priv-app/LocalTransport/:1230768000:0:1:,/system/priv-app/LocalTransport/LocalTransport.apk:1230768000:33245:0:,/system/priv-app/ManagedProvisioning/:1230768000:0:1:,/system/priv-app/ManagedProvisioning/ManagedProvisioning.apk:1230768000:6276080:0:,/system/priv-app/MediaProviderLegacy/:1230768000:0:1:,/system/priv-app/MediaProviderLegacy/MediaProviderLegacy.apk:1230768000:1809854:0:,/system/priv-app/MmsService/:1230768000:0:1:,/system/priv-app/MmsService/MmsService.apk:1230768000:94753:0:,/system/priv-app/MtpService/:1230768000:0:1:,/system/priv-app/MtpService/MtpService.apk:1230768000:1630642:0:,/system/priv-app/MusicFX/:1230768000:0:1:,/system/priv-app/MusicFX/MusicFX.apk:1230768000:168876:0:,/system/priv-app/NetworkPermissionConfigGoogle/:1230768000:0:1:,/system/priv-app/NetworkPermissionConfigGoogle/NetworkPermissionConfigGoogle.apk:1230768000:20957:0:,/system/priv-app/NetworkStackGoogle/:1230768000:0:1:,/system/priv-app/NetworkStackGoogle/NetworkStackGoogle.apk:1230768000:1842536:0:,/system/priv-app/ONS/:1230768000:0:1:,/system/priv-app/ONS/ONS.apk:1230768000:62024:0:,/system/priv-app/ProxyHandler/:1230768000:0:1:,/system/priv-app/ProxyHandler/ProxyHandler.apk:1230768000:29149:0:,/system/priv-app/SettingsProvider/:1230768000:0:2:,/system/priv-app/SettingsProvider/SettingsProvider.apk:1230768000:378248:0:,/system/priv-app/SettingsProvider/oat/:1230768000:0:0:,/system/priv-app/SharedStorageBackup/:1230768000:0:1:,/system/priv-app/SharedStorageBackup/SharedStorageBackup.apk:1230768000:25053:0:,/system/priv-app/Shell/:1230768000:0:1:,/system/priv-app/Shell/Shell.apk:1230768000:438156:0:,/system/priv-app/SoundPicker/:1230768000:0:1:,/system/priv-app/SoundPicker/SoundPicker.apk:1230768000:1552547:0:,/system/priv-app/StatementService/:1230768000:0:1:,/system/priv-app/StatementService/StatementService.apk:1230768000:2189651:0:,/system/priv-app/TagGoogle/:1230768000:0:1:,/system/priv-app/TagGoogle/TagGoogle.apk:1230768000:719763:0:,/system/priv-app/TeleService/:1230768000:0:1:,/system/priv-app/TeleService/TeleService.apk:1230768000:9768713:0:,/system/priv-app/Telecom/:1230768000:0:2:,/system/priv-app/Telecom/Telecom.apk:1230768000:10911045:0:,/system/priv-app/Telecom/oat/:1230768000:0:0:,/system/priv-app/TelephonyProvider/:1230768000:0:1:,/system/priv-app/TelephonyProvider/TelephonyProvider.apk:1230768000:443437:0:,/system/priv-app/Traceur/:1230768000:0:1:,/system/priv-app/Traceur/Traceur.apk:1230768000:11108732:0:,/system/priv-app/UserDictionaryProvider/:1230768000:0:1:,/system/priv-app/UserDictionaryProvider/UserDictionaryProvider.apk:1230768000:45533:0:,/system/priv-app/VpnDialogs/:1230768000:0:1:,/system/priv-app/VpnDialogs/VpnDialogs.apk:1230768000:176899:0:,/system/usr/:1230768000:0:6:,/system/usr/hyphen-data/:1230768000:0:74:,/system/usr/hyphen-data/hyph-de-ch-1901.hyb:1230768000:120218:0:,/system/usr/idc/:1230768000:0:7:,/system/usr/idc/Vendor_248a_Product_8266.idc:1230768000:916:0:,/system/usr/keychars/:1230768000:0:6:,/system/usr/keychars/Vendor_18d1_Product_0200.kcm:1230768000:1234:0:,/system/usr/keylayout/:1230768000:0:168:,/system/usr/keylayout/AVRCP.kl:1230768000:811:0:,/system/usr/share/:1230768000:0:2:,/system/usr/share/bmd/:1230768000:0:0:,/system/usr/share/zoneinfo/:1230768000:0:0:",
            "20": "4",
            "21": "0",
            "108": "0",
            "22": "",
            "23": "google",
            "24": "Pixel 4",
            "25": "12",
            "33": "32",
            "35": "",
            "42": "Google",
            "51": "msmnile",
            "26": "6d38312dbee54da980c9e9063395ecd5",
            "28": "",
            "29": "",
            "34": "T:1753854279628,LT:480,F:1,PT:1,PKG:1,SC:1,SRT:3,R:0_1,US:0_0_10228,STIF:,GCI:b8ba8c8,EDB:2_0_18,NRF:-11002_-1_-1_-11002_-1,NSF:0_-1_-1_0_-1,UD:0",
            "200": "32,2,3,4,36,5,6,40,136,43,143,144,10002,114,19,10003,99905728",
            "148": "686f0771-db6d-42b0-a98a-d8f3167e07f7",
            "37": "268435456",
            "39": "",
            "45": "",
            "46": "0",
            "118": "v4;-1_v6;-1",
            "122": "",
            "126": "1753668274832",
            "100": "",
            "101": "0",
            "152": "0",
            "102": "0",
            "103": "0",
            "104": "3",
            "105": "57",
            "106": "",
            "107": "com.qq.e.union.demo.union_812EDD5567C5D1DADDACB9D0522567C1",
            "113": "0",
            "115": "",
            "44": "",
            "116": "",
            "117": "3",
            "125": "8138465491340383747:1:1000_1992_1013048_420_38,2009883582161427382:1:0_5_0_292_657811,-8078172656258477214:1:0_5_0_292_664125",
            "138": "1,1",
            "141": "5596800",
            "135": "tmpfs:/dev:tmpfs:rw&seclabel&nosuid&relatime&mode=755,tmpfs:/mnt:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755&gid=1000,/dev/fuse:/mnt/installer/0/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/mnt/installer/0/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,/dev/block/platform/soc/1d84000.ufshc/by-name/persist:/mnt/vendor/persist:ext4:rw&seclabel&nosuid&nodev&noatime&data=ordered,/dev/block/by-name/metadata:/metadata:ext4:rw&seclabel&nosuid&nodev&noatime&discard&nodelalloc&commit=1&data=journal,magisk:/system_ext/bin:tmpfs:ro&seclabel&relatime&mode=755,magisk:/system_ext/bin/magisk:tmpfs:ro&seclabel&relatime&mode=755,/dev/block/bootdevice/by-name/modem_a:/vendor/firmware_mnt:vfat:ro&context=u#object_r#firmware_file#s0&relatime&gid=1000&fmask=0337&dmask=0227&codepage=437&iocharset=iso8859-1&shortname=lower&errors=remount-ro,tmpfs:/apex:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,tmpfs:/apex/apex-info-list.xml:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,/dev/fuse:/storage/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/storage/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,tmpfs:/data/data:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user_de:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/cur:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/ref:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,/dev/block/loop::49,/dev/block/dm::1130"
        }
        return data

    @staticmethod
    def device_data_map6():
        data = {
            "10": "01d82221351a6b71ea",
            "12": "d82221351a6b71ea",
            "2": "",
            "3": "",
            "5": "",
            "4": "",
            "7": "com.qq.e.union.demo.union,10228,untrusted_app",
            "8": "0",
            "9": "23417533:812EDD5567C5D1DADDACB9D0522567C1:com.qq.e.union.demo.union:4.640.1510.219:1510:1749609461905:1749609461905:952647236:1749609451"
        }
        return data

    def create_second_body(self, device_info: dict):
        first_body = SecondBody()

        dev_struct = SecondDeviceStruct()
        dev_struct.int_0 = 1753854280152

        dev_data = self.device_data_map1()
        dev_result_jce = {}
        for k, v in dev_data.items():
            k = int(k)
            dev_result_jce[types.INT(k)] = types.STRING(v)
        dev_struct.map_1 = dev_result_jce
        dev_struct.zero_2 = types.ZERO_TAG

        dev_3 = SecondDev3()
        dev_3.int_0 = 90
        dev_3.str_1 = "90"
        dev_3.str_2 = "BD4FE23C352252DC"
        dev_3.str_3 = "105498"
        dev_3.int_4 = 2
        dev_struct.struct_3 = dev_3

        dev_4 = SecondDev4()
        dev_4.str_0 = "4.640.1510.219,1510"
        dev_4.str_1 = "com.qq.e.union.demo.union"
        dev_struct.struct_4 = dev_4

        dev_5 = SecondDev5()
        dev_5.str_0 = ""
        dev_5.str_2 = ""
        dev_5.zero_3 = types.ZERO_TAG
        dev_5.str_4 = ""
        dev_5.str_5 = ""
        dev_struct.struct_5 = dev_5

        dev_data_6 = self.device_data_map6()
        dev_result_jce_6 = {}
        for k, v in dev_data_6.items():
            k = int(k)
            dev_result_jce_6[types.INT(k)] = types.STRING(v)
        dev_struct.map_6 = dev_result_jce_6
        dev_struct.map_7 = {
            types.INT(5): types.STRING('1101152570'),
        }
        dev_struct.map_8 = {
            types.INT(18): types.INT(3),
        }

        req_struct = SecondReqStruct()
        req_struct.devs = dev_struct
        req_result = req_struct.encode()

        sb = StringBytesMapStruct()
        sb.int_0 = {types.STRING('req'): types.BYTES(req_result)}

        bytes_7_value = sb.encode()
        # hexdump(bytes_7_value)
        first_body.int_1 = 3
        first_body.int_2 = 0
        first_body.int_3 = 0
        first_body.int_4 = 3
        first_body.str_5 = 'deviceIdentify'
        first_body.str_6 = 'getDFPWup'
        first_body.bytes_7 = bytes_7_value
        r = first_body.encode()

        length = len(r) + 4
        length_hex = f"{length:08x}"
        r = bytes.fromhex(length_hex) + r
        hexdump(r)
        print(len(r))
        return r

    def get_second_body(self, device_info: dict):
        second_body_result = '3ed012d4c3e0d8d9bea5648edfb228ced108b9b0005eada7b053cff49af0ffa630ba6eba4dd996126b47a6bb27644ab8c18102c17585c1c3b0af3f0b8cb6a7fdf0d49333fd8270c95c6ba6f7dc01ab37ed4b22ec98cbdd33f79f2f678ba568f17a0583e2b2dfbf8e0866f992ef8211c7c39436f110f10883a2e71f92a372945b462b4791c37fd5f4ac22950b167fab31a153f461e7460ecf74ee8a4bb45c85fd674290b814e3f96ae3282ba150c9ed2216923ad0dc72b2a5ee88e41bc6607d587209ef5de98d3c2a1ca05a8e4b36a9e3096281bc6ee656d02db176c558a7b8891833f3295aabcd6863a611bb70486340c5b3924788f06f881fcbfc617d5ff0babcb9a1bed888a647b3034856cbe9ff72e67c616aac61ab4abd488b64722b5b7b595663c9030c0b20af6b6dbe41c091fe6541b6b95a0ec75603876be7b49be41a3373b8104db41d1126ddb7e06ef525fe726b840c1c6f134d5d0521a7fbd2312f7287164a39d47f16a7fdef996cdbf1cc7cf829bf23da5fab850c9aace12d83c7028b9596275a0315e61b6cc2debaaf2dfb25a670a08ed5ebf8784650013b3716c07a9933c91d50035197f454536104327b108a039109fcfcddbab93d5a7bad2d5efc80ccd395da413108adcc632e63ea690711ab7144e3c8fb61a8a8d2bf868b5e30f74aec912c94d1ea87e31ced83ddc056fd08e0890171fd617f6dfd25d96e93acd430f0f3b0dfc21bd89de44c9649fe57a126c4abe196a72b947cd5289a6371b156ea238d2dc7b7492af3a5d0568046f76a5305c0cdac320914961051b89f5561ad6704a00d26ef70f6dc28484c2bc94a296d5dcd5e09ef14f0319eb86bb707bec0f1145c9d28c0c9e3afad6fb74bca021ebbc9b979b85b94b12dfcb717642f5307032eed87255109a501588baabbc226e49029363c4c0b14063426db52094997a2addd16b9764a3805fe983cf790a986a48eb5d2fd438acc65a9acfb345cad78ac7d515b95be8114e5cbfbce25c30a12f10ab144a8aaf051db134eaac74b2f4021b76fd83681d91c8d8fd160079243ee6d9a34cf782d60e53f7be33eacffe353f9ecf132cb7120ffb9e712035b79499113f4f1212f712c23d2811e2205676e4cb52bf4892c761eb10bfe521e521f04d235cc186cdc9a0e966725c3ed691a0b56022e4f9dcd5cf84b961b8388a34ef19109d4f77e65ee8114766d0576da9333d3bf2f3a1265b33bd17ab66620960222dcfa53bb3f765e3c8689993361ebd48e6089cb916a9f3885a3cff4cc60884475fd367e8a7ec012b88064d6fd8e446ffe7f60c85432b7410e7f94ee8c5f9e685de1a334c057b6eb7a5e730ae0e7b9d81d7fe793e8c67df081d4649b6c8b521daeac18eba457254668b8abc4c772ece314b146fcb205c48e17a0ff153cfe6b23608c37a8b879e01aba72ca7572bfa8bd2a93b7fee72933e752280b92282fdb4e84e31db803944285a03b3eeb9d42853010aa13df3f72aaee9f23c1b58bd58a2b135edae2ec62161c66a01e341f2d468d2089d378f856002bb3af619a8f2b0caecc040e5fad5beb8a10afaa7c76242bd41d59eb65258a2dbb5a1656686bd5be264e0482e4361ba8ba7f75d0d1dfc88efd7addf201f4c926173350b426ac650815115c1f16dceea6c0b00fecdb15e13dc9dc1d66dbd64ba1e75bc7ee9b050ca5de7efe998027a17b9a4b0756985115ecd26df9dd9c760cba869b02348f78ef3e907738e1ea48dfcbfc3d7b4ff98e3c09b3c5e9adf65f6022dfa363d9528d7a99902222706239955f2e85307095d408817553ab44a0ee23b5669a63e3193d73caca1daefc8ab3d02e0ffe7266b188f7123525d1af838231015d06d14824a619799bdae2f526f288b7d95abae79e054ee4d9616a02f3efa6de73d211ee00be159dca8940040135fc8caa99537c92a3da34cf829ff4c6784a80355f5a8b8615f8ced34930225ffa3ff4a2b8a430dc72b81e32cc51c6772e7ec4de09e9cfdd391629abc033de9764e749d1dc438653401ca61807c0165c68ea14aa631505f3541b8692e11a894ba077b0c81bba99898492a3922ab6d72bde502f4e479e7b73d1610a881d560e5ee6bc644b2d6508fae408f30b5f9057391c38b4886457966c7b711e03e8e75589876a7b249e35efe37082dc53b6f0d5ddf2cf86c79f0d5c67a19d0e2b729821d4a0b6a1c77f75b65a6c4c9dea273838e7f2331b7efcbbc7d3ffc5027f15955dbf0d0da2523a17a2a72c04821e11c0ca03c5f7abb82364e39fcd7877b985be91a4029b4bb8bc250c775bf537922d157dbfc6b326fb224b4df3f48f0f1f8707d8eb674460e0b5f2dc909cc18bb85115944f41e71efdf3073249217cb8a02a090beea6ef9341ef4a217391d405ca525df3a425188275bc4b90c49bc53232abc35ae03e34db2394fb8054e4c9a8a95bfd337f7631a995a654ea1e158e92a7b3abbbfa03b336a49440d3d04e57b2e95490faf6c61cf36db4021e5906b9e1e4b9ad7a45e1b3ed7dc60495ae181c85283ff20929ffae7bd248b5d4e546259b62bf5855a6384a301a911662a160d8aea71a234e835e08ab9122e3d112a742516ad3f82b6f0c54e8b4e515098fe40595ee00dbf9c0db3668746edd80ea17907f1fa9ebc56dafeb79ce8d1a448297d1e5ed727b1fc53809090c1c17d05018df216f6b78d206ca883a7cf1e7eac6c7ed97c944dfd3243edf7ebfdfdc31aee5972ed0b50cfb8ebe921b914f5b70114072c1a163a996fc5749265611881d7977d25abf5b3bad35acee7236de5e9a52d48f21c29a0b7b14a9bc5ae2e639a293f1a6e26c1f43ddb0b48d7a8d636a31c51cc83b24549c465e1c3dc7ad70cc22edcb9cdbee31cc4e0a3106ec905875b2e9af7b06ce672f44e80bdaf956574f16da2ee1b1f24117f41ea233c790014ff92ddac6edb487e18dbcd92a15c2a0fb833da70d4acc9c164fa30a213961f0420339dae78270b4f6a415ae5020721f65cca141b14b39d034a099204a373f5393f9a9ff3fc2be5163e2ef2773621337e29b15a788ebcf47fc2cd8dd89fb6d674473d7374bf2354fcb92eecce8f9392f4fe88eee8b68515f41d75c928c37acd3364a89c6623f69197425166d2dabba1d7101e045a00da44af002cdecb8fd1eb27998f31bbb91c1d7e02a49720ca72aca5404c044a68610d84970df7e7e271137745fbf72c4425075ee5a824ffac37ca79e557d3a110507acdf2fa58979ec2a7daa9b503f36ef78ee4063f314a3244136ac84129b1071c362ae627cc438a4980740f4ea5cb0835416d53fb4470eb4fc4d442bed229b698b3a4b55dafbee80059bc1d03e4920a8fcb12948335b79c41445ef99c7d50bf591b46779f8b7a3f6508c8721e045d4f4cf03616d9a5061a80cc1c9b209461474ed23c6024024cdc91b082eb89c8223ad84cc8b238cb219f5853037b6687a96ed6388bd034c9e005e372c2f399bd3c94405624ebe8d10d95b1be5a690b0a278ad0a780c7881d5b8c535f8c733bdb8ca756a3e2aa42a3062fed519008d29c44a465abb542b8c5177890133a0716f68b7724e98a81620d42de48e6020c180873ae6d9a8df1dfc6f3de494b7a9d6ce654322ea2dec72a4fd992aa777da8cc1ef7b69025b0c06377988fb861e6d9d6f5b94d31a6022f7000c833d5b61b1d42b821dcf4e542215d1e0b28904b4aea4791b573b0ef84c3477f585eed6d8747631c089c46ec0d0b3d38911253ce65625b852b53172f5731873ecb852f897a5ab8bc2b8de3fcf1c3efc9fc2606089e91e80c8fc86e6bd1e07182e52c95f7c4b75e3fff867fc90cd58e823c8d4e804fcd58aa511730a952d28ac48a6dfc9b3c063421d157216b5041c207dad5f96e22789fc1f049a808a3fb477e9c964d4c3ada31b40c0c985ba1a9595f8892edd5f662b6e2911ad9f659c1ced77551f1305798216cd999eafe54f929bfd8231a5a318ac22a64d55fbaf23d739366c401273a9d6ba7f761566690ceb00145d980ec2b84f41acb2c7ac1b5d96224667eb761c9368c2f0e44a6925a1d65a4672df0d7b9e9b4f25f6c2aabb9341d07fb67a6c83e69a0385363819d1651736f2dc6993854ff3e541d0210e4f703dcfe5f08434434135e3f6e80a46d55a3337b850cab3a9cd93b8b0e97f8004566b7eefbdd1bebf26cb1377b2eb3799087b6c53f935eca72c564037adc6749092395d274c46b8b5bba30d272162426e40beacc889a2f3363c0b24ce0acdf2c56cc8a34362788cafe569948ce7984920db8d0d215c866fd901e74cac921e84dc5452192e06a4d3dd46847f1bc3482a38481d10df9239cabef8faa2b6a4cc74eaa72cd74a1acb48d09f6fc8aeb452dd931d69328ac6117097d69c71f723c4d269712a376ca022670be244f52cf03bdf5453f234af676f3fc96c14b976e3b19bce412ea05c6f307d8b58421e04a359c9d85c8eb2f623c294b4c81477af6aca8d0b53f54b00012c57a2e688ec06de29c514204ac7ea161f0a72a22e56f475bc6ffa3df81e946b9369c03e74ab44c807f7753dd30695eea31a0099996caac3ae4c3dde4c3ac0cb2522b82ff524d6328155ac3bd25b93836c0d8289b5c15d2259d0e88838b0e3ee41cac0e3fed304dbc16aaff9e827bc0d81ca0796c1de55fb6e64ee8edba67a65aeba65ac1e5a66773b0cb6d6995adf6445a6ddacba89e1a27ee8b8c191e8d282525ebfa414b898f26ae94ea30d56f282723f3f3f342c3cc41351ce7ae2d8e7839014bb1db646a6c3779cfeff539a87c05d853f77ef453f1cf041cd7287e73c52b429b945fc9a7cd8b51a4fae95fb2abbfa686d36176a4fca5d9ee9ef868b5f3796c9477ed0e17d231c1c81d7e0bdccf9045a6edbdafddd046e5ba1034ded37404b4b7ae798d5138eb3056265b09edb1bd247878a9a101bdf09b32c715badc3712f867c2b21c4df71e59f4fbd04a4a680ea0fbea3368b1c3632ee02f05b36eb419c571ab1ad5f560a7d3a502fd9fc28985be676202e4d124f3e02eec03ef92bbe5723dae97c4b51d72e4f319261760948b27148fb1a0f315891b2722ba07d5d80e4a185ce53fa4f921d23512062d55a9c6a1a4236c4670708473f5a1d32252dfd5d20c45247dbf4f565207837280e3e295a333e2c64bc328e7d06567011dcb99ec8da26f5b512838a7236473be972b9bc8a1a613c7d756c008cd41bca0b60091f1a224221f44e2f6042e729c5a977c78f2fb3d23ed7deab4cc4e5a107d216993433ef07818652b1bb191a859dfb60754da8529cfceb6a639f595be9bef857f68f69eb0cad46da0f3e604777b895d1a33a7c595fc4312d0be9a45898a058f367da941eb38fe97c90efab9f1b4d1859561baf598ec10dd0909b3bbd84c51ee2d22fd9658a4bcd97f306361e7a867b34bc14123aca5e9732dfbaef1993f48b9d7318cc9128fed5a5524ca125693eef5d885d0f5d0c254f075b8ebc7c4c7c5d13baba8ac47be917161934158c89c56f34810a5a876491d50631a4115f991f8fe37ad29136d2e3b9d79be88edf4d915d907a74b341fc648a614b664413841bb5056985f1da07e65bcc6aa088082a1493c7c07942be17f218eba47a2c4901d6bb39a7506b5c57f60eaafa3d981756eb568091d9948761497aa5ec81fa248b22fb940ffd371045dcd1e6e9f8e2bdff9626692ef473f4812d8167add5301f43c56a5efd644a49517a9869b61aa44ac4240fc76a41badc082e4fdfe17ca1b54e1b3559583a0682249ce6e25b788684d71cba074c307fd31060ef70e186813ae4acca32f5231889b58e6bcede799dbb126f38c07b13a51fbedf1e5472abcdf23a6a453c687b8c425507b3f2d7b29cfdfd53c3a658f4f6152be0681b3d448b8754775d167e32629e258e394e535b0d2cee99cc36e907bc8e530828106cb5d243d21f0f76f05705eaac5dd0c9c396d5570ffbfe62f470719a744d4e8b3b4d901894c578b4c7645a0ecb81d2d2691f64019dfd0b6a8e90a73f1d5797320f36408f7a865b3e0fe24d5d66e0bc4d9aa5195ed2a25f4e84281472f3a8fee8c42689cd4cb8cf3d7cf64893'
        jce_bytes = self.create_second_body(device_info)
        zip_bytes = self.compress_data(jce_bytes)
        # zip_hex = '789ccd5beb6ee34876a6bb93eee9e9d9ddde4996b31b64834e66e3000b5deac24b5119016b5bed5eefd8bd9e96bb6767fe08145992d8e66d78b1ad0666800001b208921f0102641e218f9247c88ffd9727c80b043925cab2c82225f560100436a962d5772e75aaead4a92a5251faed27f75b9ffceafeeb1fbafcca73f889cbc3cc9bcc278fa63c1b1c9f7f9ec75f2b7b9ffccf7bcade83fb09ffeae7f0f0dfefdf5794bd6fbff8c3dffde74f154be9aa8a82e142ea9331a69a35a6c6d8d04dec8c91f210f2df530fa75134f57977e2dbc1f2dec3a43bfc8c1e74084126d23b08d1ce01ee32c3248418bd3ce54937e13eb753debee4f354f940fd8bcf72db77a220b8e0ce2c8cfc68eaf1b475123ac3338675a4fc407d4018421da43c52ffad0bd5e98efdc8b9ecba415bef31036103b5b2209ea43d625a4c43d5a73289d123cc328024b0a75e7ab942551ecb44660fb299c12ad9ac47a88574802befab3fd631b6cc8ec55ab709e5f14760cf2fb379ccfbb8178275faa7c33363307cf9f4c071c0084914f08c27bd2b1eba51d21f5e9c794e12f5129e467e9e7951d8875a23cd64baa1e9b4d75a70224b4e27437236387d7a664f439eedc2082f196865559ecf932875a2986f510313820d4bd3975cf482cbc5d9809a88bc7e7a108c3de8624f4fbde92c7b3ae4611aadf439381b36e862145c0ecfce29434fcf0194e609af901f827e33491db3d7527ea83ec288a15f12420de547ea4f2e667c34f6a623db05d20c3875a2e95479a23e314c1d4f88831dc3b2b509d7951fabff857bf087a05bf6b0a9591ab50c429961f5a02b76b2287e13cdc2ebbcb3ec173d8c19c216253d3b8ebbdf7cf3a571793279a3bd3d23dac9cbf877f4b97d757470d0ef77dbbfbd1eb137e1f5b18bb2ece218fd860c1d3dbdeeb76ec5b1853803599a81a1f32cc47df5558777f210ead671791015c91ef42e0d9b3aa54b99af2818e7f9c1ab57a7e4e0d5d9e1672f5ec4cf9ca990e969d7a179e47e7efc726e7d31fafc28fec29f3dfbacdf523e841ed8fefb6e3a4f331e74617052641a3098500ff5b0d66bdd96d831bfa91413bd522c14b54337893cb793e4e04d02de1105eb640c53822c41be461b5739d372e9a19d7ace20e1769056556c06aea5418bcb753a5d83315355e1d0cf619844d9acaa4c136c95aab2a78c5062e06601be37ae0869829e79ae37e48970d05b6a5e47519759559658582392fc28ba0cece4f23c89ae3c173cf266d9557435433210d54da32af308c679623fbbc9606843e74e81f866be59703d496daea48249a926ab1067de153f8f92ccf64f619a099f17f3d7162d1aa89a0ae4ee68218bcaca2489c793019fd8b99f1d488344d2a20a9772aa7231cc63a62ec9e5497612a6a0b2bfade1cbd0d2534d1d2d22b77914c4b6706583450c726687f674abd07a9afaecaa1a16385869e43fb321993c9b4e370bbe83ad52924599898929f5aba2d9a1470e6776c2ddcd62aae0cab324d2607a83c0f3c40bb3975c444e304fda6266dcc9976ca5de0690acae2159c75f5f9c9dbef6f8f5b6f65ec3dd25658f424dc98b7dcae74733db0b373bf415ea3651e3ad2c24bbf3155d64679bbdf9293881cf6154c4301926e9b9e75c6eab732d455da6e4cd2106c1b2255e4c9c178eb7d90e4b4cf123f14516d3ad26be5be7b373db012fec40f0166da97909b9fe50a3915e2327c9429edcce3fe96ef35723555381a48b8e34c9b72d86c7308e22d98d920dc8f587aa1c5307ff25b9af12f9d6a6187207c2de673e87415bedb77813b4f454d58c191a932c30f4029875069e0d2bb62d92d691eb0f72ff865e28b9926176b9853f00e092b861dd308864a2d5203bb49dcb5c0a4e37832bcf75e196b54de0468f32961cda7a61eef96e274ea2781da261bd2493674e858546cba5e3edc1701936ce4630f33b971d270a27a5f9c9d24955f6389e54e5cb00b17c1879a1609bc132adc41319ba5165ea4c93288fd3ce9b14564615b32cca7d3b4d633b9b55d710a41157e4a630a9f16495dd89c7255da8294912a148260ce155fbbdbe0199169367da8e7d3b9b4449d02e8adb4579e726f0cb9d9752a95527e9a8408f5c2f491bbb89807aa157ed65d04b64c8ecbab9bbad40790c01001ff110825cde499cd2fc49689506ba7ae0a58be8bc3a70f566649c7857305cda6b79ed6283a96a1bd3b4a4fe116f8aa06f015edccee3f6551c969a18238d55d9257cc35af416e0051084567115462977443b8fe2c8f79cea82c7d88875123b9d8ddc3c003793049d22b7147597d7384b1679e26555415a03cab11d08eb45154c9d1a06238cd656a1841e4deb964d4d4493148697ac51133cca0a219db75ec9c91162488d9472df0bf3eac6056e4005d0b9bcb03a641bc062908e66d7cb412b465dc66fb2b4cef39448525e34d3c80eddd15262279dd9043cda9a5c4397b8ccd35a97429b6071c2bde572cc6dc7e09b455f5c3997ea90d1a193574566767a3982c964e2f9522f36364197be784451a33b2e13949e46841564e579539a46ae20eea94e24661da4f0a3ded8f3a10381d1b3c4bbe9e8550b60a2c1c4522f2480a5e584a71ba6e509740069664166157050ec8f1d891de24e9695a64a4dd7ca2c133be0d751520d6e745c87010f5015df881bc39cddf68254cc3041042b9e242bbb4f560eb24ad486b6ab1c406e91c4b0451aeabcbe9b184e9c118c2e70779d37765252d52ac79d77f47210459a60b2e91a39d6d57f0d5c84dfebae925aac5c2c2c9242556036aa217617aaac33c032007e27d7aee842cb09372d8547d442e5c122e816d3784931a9dcce5d2feaccb80d0b8ae9c806bbbbc5de51853fa696659437f00407b8decec55ef8027e278a10442c092d622908f1bdb73c698328bfedc471458ec610a91a6861fcf56ae80c57011b2d0ce5db6cbc846cb1b26e21b36a65a0dc62e702b1b3a599891863b29492ad758d32468c1ed574c66aeabb83a92df82d8911b1565bde99a7660da458b5bc04f71825fc484c3e49b0d80e6a0e9076a06d2c9157dfacd21befb82f5acf7d9107639e6cdf0cd842579b2bed1611adb25974c7151667d94958acd76b37e2c88e543579f2862ba96cec6fe4b871df60457964fb62abef5d4c2991543324c52d705fb449bcd847af5d9637c85ec3979ee44d3ea2e9f542b9ef1f2691ed3a769a9df2a9edcc376ec66f23accf96f7e62d043ea45e2388246c27db6177ab99a49a216dd99a108c98b5e20791938b3da0f4d5c9b6e3910d34524e550303c611a1f56d3288ae431f4cf80e169048aa19d2669bd8a9d94dfcabead6ea2e0a00919c25f936c3244dcd300fedc073868bece5b9cb6e7bfcbbb3d806900f2310c55aadbae23c2e096d7f08ee1c1622efd0724d940df9523b228cac5a958ef394bba791533757d579e232bef45415aa618dd6375b99c9c69dbe15cdf2bca558c2ed7036b78db03e5b76898852b33e2a3809e33c2b4eda366ca7d5c3d71f6ab64731a977fe251ebbd94d98d9bf48ec308da364c366771341f971f729a3387c2c86b5d8a6923715ea84d751d5e4497e92980662f50638e3ae67df0e8c62aed945911aaa9a3cf9f0531c12d58ffeb320dddd2dad81ef92f2992204d9f5b2b2f81d64dd81ef92b25ba3c86808a6cef2d4738e7fb78ba82572f95b7390cb1ac2d8173c130bd0f3d5bee7221c9eee3cfb6ea6df585a77ec56efd8966c86e214e05d355b2792b3e48ea6115860d56af1db17c31dc40a145cf25042a4beff2ede21f9b51dbabbf9dd127cfd61eb71d08ac59067198cf6a620afcecb4a24d50cf9251846b47a072ff1dacde316ef282c67e49de3f43aaa9abc9a63d70617309c4190bd9360815bdca5199c32acd7f7b1619487eeb663fc5af45a5aead4ba4e74ad7e680dc51198089677f76b124935433e0b6596a1d72f5c2fecdd7dcd1d76959222326c99467dc35d709fef5ec975f45a5a5ecb18cc6c58520a322792764e372097bf52fb214b9c13d50704b7b4bb0d22818e6751387f872059a69172a41eaed1a62015621e87e73bc95d2297bf9255c026cca4f553e7ab942703cf1181b09dbc4b651b08ebb3a56aebe285d93a7d5ec761f1d6c18693bd3af05d52aa3efc5a25ff9ea7d50a1ae5c2d93c9ef1b0edda995d3ddad09a9122dd7679db99b5b1857067362f1f52c3c48659550fcfadbe0660ca80d78b57ac47304fd82330a99b3bd98811c3e84061699061a3caff92cf1df0e21b4e8e4aa8a524cc5cbc928408429d4b272857a67caab964e2dbf32897827c8335010f5ebf3c3aef5c968e8018c655cea998879addc31d641c545fecabe5f4360ab9174e2209abfca9baa7293f51f790e28b9baa2aca47ea83e22855f9a9faf0dcbbe1fe534df9997a0f13e52fd57b94281f03e897ea83c2cf2a547d18a441e841f2cfd4a7864b19c5c41d73ae6bae6d31e458dc4206a596ce1d5757fe1c887f0ed75fa9ff72b1d8b386e89d98964158ebf442ecbeb78e7bb8757e216e9f3e87fbf048dc5e5ef468eb650f8d70ebd5107e2021de5a6f0d2f4e8e7bade74727bd311bdbcc61ad6783c31e11e5acf5e2e571af0dce0091511b17ffcb87d68be131702972c56febd5a087f694ff50fb94b4488bb6b416355a7acb6869a88521a9d1165e5c5a0b7820d2c21852d6e281b62ccb42ba49d89ef2afea2f0c664c9069e2b63b36dcb646c6a80d86b0db2e9b506c981c991353f96bf511319846754d3794bf0183b4e1ea8836b8521f5f697f0b7a5d197057de42fe37ea0f6eb7f74d8d4113b890c901bca77c2b4826e23615b799ba47154fbda79bca1bc05caacd6ff28f1826cf06035d37cc237d80070783c1c1d1a135403a21220f2b5f098e29b069c195c1950bee5fab5f334c9966e89a85a986a0c14d8821c4770408cc6e5904da0653a4b19146d088b2168c278b31aa33820d0cad4d1901381ae9607a027043376110b4da0cc1af490cdd203ad34c9360ad8c33344cf43de51fd5fbb885f7947f561feaba257af39ef20f1f29cac34f8b6f6cc4f730bd22995cefa7dcf1ed31f7f7c328cd3d773fe1623b29e0fb41e4f2bea9ebcb2f73ba419835538500be823bbfe18ecc627feab97d51ffe25b9c499ef205bfaeb7daff405d1ee440c6dddea21864f8f6dbf9824d9d8c302a44888f9346c01ded2fceb78b24b08cae475136e3094814ce38106be56699903c28ce3517f05eea3a76e21655dd247d228aa0668442727a9b2c1258df07ee992734dc0fecf4b26fecc3dce75df11100f697a74ba3304a02dbdfcfc3852f7247d178bcfec5d2edbb01dd3472bad815df39a14e3e49674e773c6f8b0f71c4fb38a9976645ed8acf6f5679fc26d336b557510d51e77e948076dc5d177e2b21e099bdb0cb5d6a47c65e2a0cb9c8f545ab38fbe2d0d9cbfab810fa26cac57ee1ed975c4bdf2c0e96c54b75b7fd2dba132377cf7ad2ee327b170eeb358ea2acf8f8eeaef2000b4650f7a569c5a1d73534d5480c88ab899d09eecb774dfaf9c7d1f80d875932f97885132f507c9ca23bc1b7a3617fb2e816624b6fdf2d928498c0cbe531acb0fa100aee7bd16226e659df4b23c674ab8df7d35994648b6fb0a09b43e7e2491225693f01df9587593b896e87ece24b9fef3866d7792c6e6d3145b67de8558bb734be2bdb350f90162bc9ff93915f95f5ff6cc4df7a66a1f1429fef665e5c6224f4f8de188d5cfebdf00ac02574efde4acabf1f0dcb5c133ef9ce5cd79c811f4571afa759e52f48c5678514b57aca97ea3d0bed3f391c68c7cf083da22230208323e3014630f7b35fdd7bfc9b077fa2750c0d75b08e518788780812eacf1a838ec75f3e50f6954f8e95d7cae399f248795ffd1081d3278460aa63db189b98dbca07ea1329ef1ec41ff7e1fa63b8fe08ae876abb514aab080ec1572439f84c77048b27e53d11cd3c527fbffa7e715bfcb3e123c872a57b2251f980b2fc64e9c4d04c428d55be8e6f943da8ccfb109262ac13dd44bf878c0f9fdc7ffc4fdf7ef0ef1ffc2f22c75ece'
        # zip_bytes = bytes.fromhex(zip_hex)
        body = self.xx_tea_encrypt(zip_bytes)
        body_hex = body.hex()
        print(body_hex == second_body_result)

    @staticmethod
    def create_third_body():
        body = ThirdBody()

        dev_struct = ThirdDeviceStruct()
        dev_struct.int_0 = 1753854281166

        dev_1 = ThirdDev1()
        dev_1.int_0 = 90
        dev_1.str_1 = "90"
        dev_1.str_2 = "BD4FE23C352252DC"
        dev_1.str_3 = "105498"
        dev_1.int_4 = 2
        dev_struct.struct_1 = dev_1
        dev_data = {
            "21": "0",
            "108": "0",
            "7": "",
            "10": "51197.98,51197.98",
            "105": "57",
            "14": "1080*2236",
            "101": "0",
            "152": "0",
            "103": "0",
            "104": "3",
            "33": "32",
            "11": "type=1:name=LSM6DSR Accelerometer:vendor=STMicro:resolution=0.0047856453:,type=2:name=LIS2MDL Magnetometer:vendor=STMicro:resolution=0.01:,type=4:name=LSM6DSR Gyroscope:vendor=STMicro:resolution=0.0012216945:,type=5:name=TMD3702V Ambient Light Sensor:vendor=AMS:resolution=0.01:,type=6:name=BMP380 Pressure Sensor:vendor=Bosch:resolution=0.0017:,",
            "24": "Pixel 4",
            "12": "QualcommTechnologies,IncSM8150",
            "23": "google",
            "8": "google/flame/flame:12/SQ3A.220705.003.A1/8672226:user/release-keys",
            "13": "2800.0",
            "25": "12",
            "20": "4",
            "100": "",
            "22": "",
            "28": "01019C1A6A4B7CCAE1FF35048332F0D8A7AD907D8E2F8FD9DA05DD69193F60C909ACD043F073DE6204CA83C6",
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
            "48": "b1349b36b6571cb0",
            "200": "32,2,3,4,36,5,6,40,136,43,143,144,10002,114,19,10003,99905728",
            "116": "",
            "117": "3",
            "119": "unknown",
            "26": "6d38312dbee54da980c9e9063395ecd5",
            "45": "",
            "118": "v4;-1_v6;-1",
            "120": "rwxp;/apex/com.android.runtime/lib64/bionic/libc.so,rwxp;/system/lib64/libselinux.so,rwxp;/apex/com.android.art/javalib/arm64/boot.oat,rwxp;/apex/com.android.art/lib64/libart.so,rwxp;/system/lib64/libandroid_runtime.so",
            "121": "",
            "122": "",
            "135": "tmpfs:/dev:tmpfs:rw&seclabel&nosuid&relatime&mode=755,tmpfs:/mnt:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755&gid=1000,/dev/fuse:/mnt/installer/0/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/mnt/installer/0/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,/dev/block/platform/soc/1d84000.ufshc/by-name/persist:/mnt/vendor/persist:ext4:rw&seclabel&nosuid&nodev&noatime&data=ordered,/dev/block/by-name/metadata:/metadata:ext4:rw&seclabel&nosuid&nodev&noatime&discard&nodelalloc&commit=1&data=journal,magisk:/system_ext/bin:tmpfs:ro&seclabel&relatime&mode=755,magisk:/system_ext/bin/magisk:tmpfs:ro&seclabel&relatime&mode=755,/dev/block/bootdevice/by-name/modem_a:/vendor/firmware_mnt:vfat:ro&context=u#object_r#firmware_file#s0&relatime&gid=1000&fmask=0337&dmask=0227&codepage=437&iocharset=iso8859-1&shortname=lower&errors=remount-ro,tmpfs:/apex:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,tmpfs:/apex/apex-info-list.xml:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=755,/dev/fuse:/storage/emulated:fuse:rw&lazytime&nosuid&nodev&noexec&noatime&user_id=0&group_id=0&allow_other,/data/media:/storage/emulated/0/Android/data:sdcardfs:rw&nosuid&nodev&noexec&noatime&fsuid=1023&fsgid=1023&gid=1015&multiuser&mask=6&derive_gid&default_normal&unshared_obb,tmpfs:/data/data:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/user_de:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/cur:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,tmpfs:/data/misc/profiles/ref:tmpfs:rw&seclabel&nosuid&nodev&noexec&relatime&mode=751,/dev/block/loop::49,/dev/block/dm::1130",
            "124": "",
            "125": "8138465491340383747:1:1000_1992_1013048_420_38,2009883582161427382:1:0_5_0_292_657811,-8078172656258477214:1:0_5_0_292_664125",
            "126": "1753668274832",
            "34": "C:1,T:1753854279628,LT:1534",
            "129": "8,wlan0;69699;5;fe80::3e36:962d:bd07:8d3f;fd0a:a5a2:5da9:0:26e:65f6:d987:41aa;fd0a:a5a2:5da9:0:9a7f:9f6f:bf43:8c69;fd0a:a5a2:5da9:0:aab9:7829:b15b:f5f2;192.168.100.116,r_rmnet_data0;65601;1;fe80::dd49:1161:3b30:3f7,rmnet_data0;65601;1;fe80::3d03:d5ad:5a20:8dc6,dummy0;65731;1;fe80::e429:bdff:fec6:3064",
            "131": "0,0,内置屏幕,1080x2280,131,1,0,",
            "137": "-336568457738497426:0,7026921823820558012:unlocked,573726331679131030:orange,-8233870966039513836:enforcing,-8268411640757575412:0,-3970424417706690388:1,7247450386580705748:0",
            "133": "android.content.pm.IPackageManager$Stub$Proxy,,",
            "140": "0,0,,0,,ffffffff:7:4f1:fb:com.google.android.marvin.talkback/.TalkBackService;0:10:120:8:com.google.android.marvin.talkback/com.google.android.accessibility.accessibilitymenu.AccessibilityMenuService;401841:9:1f1:89:com.google.android.marvin.talkback/com.google.android.accessibility.selecttospeak.SelectToSpeakService;ffffffff:ffffffff:53:2b:com.iflytek.inputmethod/com.iflytek.libaccessibility.external.FlyIMEAccessibilityService",
            "138": "1,1",
            "141": "5596800",
            "146": "2,272496640,wlan0,fe80::3e36:962d:bd07:8d3f;fd0a:a5a2:5da9:0:26e:65f6:d987:41aa;fd0a:a5a2:5da9:0:9a7f:9f6f:bf43:8c69;192.168.100.116;fd0a:a5a2:5da9:0:aab9:7829:b15b:f5f2,fd0a:a5a2:5da9::1;192.168.100.100",
            "147": "1,-4516327767009073080:715a7760:/system/framework/arm64/boot-framework.oat:FFC302D1F35305A9:r-xp:64773:1178,-4844424437839471813:6de5000090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1832:108,44102712923359780:6de5000090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1832:108,4353017571826496965:71603610:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,-4153032832367424344:6ff90880:/apex/com.android.art/javalib/arm64/boot.oat:F00B40D11F0240B9:r-xp:1832:63,-5151164676057608033:718c22e0:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,288159253053431654:71949c90:/system/framework/arm64/boot-framework.oat:201840FDC0035FD6:r-xp:64773:1178,-2980294074726822096:6de5000090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1832:108,2559244107516066520:6de5000090:/apex/com.android.art/lib64/libart.so:F00B40D11F0240B9:r-xp:1832:108,4473348173689220732:718fe480:/system/framework/arm64/boot-framework.oat:F00B40D11F0240B9:r-xp:64773:1178,6869870101328312217:7015f100:/apex/com.android.art/javalib/arm64/boot.oat:F00B40D11F0240B9:r-xp:1832:63,-3709677853439453148:6de511dcb8:/apex/com.android.art/lib64/libart.so:FF8304D1E85B00FD:r-xp:1832:108:183:2b417e2566f5eb686666666b6ee952ea:1832:108:FF8304D1E85B00FD:,7196916155523678026:6de50d75b0:/apex/com.android.art/lib64/libart.so:FF8303D1E007016D:r-xp:1832:108:183:2b417e2566f5eb686666666b6ee952ea:1832:108:FF8303D1E007016D:,-3379978139409198809:707ca36c5c:/apex/com.android.runtime/lib64/bionic/libc.so:FFC304D1FD7B0EA9:r-xp:1992:38:183:cd7952cb40d1a2deca6420c2da7910be:1992:38:FFC304D1FD7B0EA9:,1907461101413668651:707ca82758:/apex/com.android.runtime/lib64/bionic/libc.so:5000005800021FD6:rwxp:1992:38:183:cd7952cb40d1a2deca6420c2da7910be:1992:38:FD7BBEA9F30B00F9:,6233979380418259349:7090795310:/system/lib64/libcamera_client.so:266BFF17EA79FF17:r-xp:64773:2058:183:826efdfa62ce3adf1b122c6275effc06:64773:2058:266BFF17EA79FF17:,5658918889255550592:7090f60a50:/system/lib64/libgui.so:FF4302D1FD7B04A9:r-xp:64773:2138:183:4f3ece839d06b871ad524c10bc06b05b:64773:2138:FF4302D1FD7B04A9:,-2494213541457932276:708d66bf40:/system/lib64/libandroid_runtime.so:FF0302D1FD7B02A9:r-xp:64773:2005:183:c6c03d825572c9076140b9f76c653766:64773:2005:FF0302D1FD7B02A9:",
            "149": "zh-CN",
            "150": "Asia/Shanghai"
        }
        dev_result_jce = {}
        for k, v in dev_data.items():
            k = int(k)
            dev_result_jce[types.INT(k)] = types.STRING(v)
        dev_struct.map_2 = dev_result_jce
        dev_3 = ThirdDev3()
        dev_3.str_0 = "4.640.1510.219,1510"
        dev_3.str_1 = "com.qq.e.union.demo.union"
        dev_struct.struct_3 = dev_3

        dev_data_5 = {
            "3": "",
            "8": "0",
            "9": "23417533:812EDD5567C5D1DADDACB9D0522567C1:com.qq.e.union.demo.union:4.640.1510.219:1510:1749609461905:1749609461905:952647236:1749609451",
            "7": "com.qq.e.union.demo.union,10228,untrusted_app,10228,,init",
            "10": "01355f59125862089a",
            "12": "355f59125862089a",
            "4": "133_0,138_0,140_2,-17_0,145_0,146_1,149_0,22_5,150_0,151_1,24_0,100_23,101_36,102_1,103_0,104_0,105_1,106_6,107_1,44_0,47_0,48_0,113_2,49_0,115_4,116_1,117_1,118_1,120_17,122_0,s9_1,21_1,7_0,10_0,14_0,33_0,11_1,24_0,12_0,23_0,8_0,13_0,25_0,20_0,35_0,42_0,121_1,135_3,124_1,125_0,129_0,131_1,134_0,132_0,137_0,142_0,141_0,147_26"
        }
        dev_result_jce_5 = {}
        for k, v in dev_data_5.items():
            k = int(k)
            dev_result_jce_5[types.INT(k)] = types.STRING(v)
        dev_struct.map_5 = dev_result_jce_5

        dev_struct.map_6 = {
            types.INT(2): types.STRING(''),
        }

        dev_8_struct = ThirdDev8()
        dev_8_struct.str_0 = ''
        dev_8_struct.str_2 = ''
        dev_8_struct.zero_3 = types.ZERO_TAG()
        dev_8_struct.str_4 = ''
        dev_8_struct.str_5 = ''
        dev_struct.map_8 = dev_8_struct

        req_struct = ThirdReqStruct()
        req_struct.devs = dev_struct
        req_result = req_struct.encode()

        sb = StringBytesMapStruct()
        sb.int_0 = {types.STRING('req'): types.BYTES(req_result)}

        bytes_7_value = sb.encode()
        bytes_7_value = bytes_7_value
        body.int_1 = 3
        body.int_2 = 0
        body.int_3 = 0
        body.int_4 = 3
        body.str_5 = 'turingRiskDetect'
        body.str_6 = 'riskCheckWup'
        body.bytes_7 = bytes_7_value
        r = body.encode()
        r_hex = r.hex()
        ori_hex = '10032c3c40035610747572696e675269736b446574656374660c7269736b436865636b5775707d00011d6e08000106037265711d00011d610a030000019859dc85ce1a005a16023930261042443446453233433335323235324443360631303534393840020b28003c0015160130006c16013000071600000a161135313139372e39382c35313139372e3938006916023537000e1609313038302a32323336006516013001009816013000671601300068160133002116023332000b170000015a747970653d313a6e616d653d4c534d3644535220416363656c65726f6d657465723a76656e646f723d53544d6963726f3a7265736f6c7574696f6e3d302e303034373835363435333a2c747970653d323a6e616d653d4c4953324d444c204d61676e65746f6d657465723a76656e646f723d53544d6963726f3a7265736f6c7574696f6e3d302e30313a2c747970653d343a6e616d653d4c534d36445352204779726f73636f70653a76656e646f723d53544d6963726f3a7265736f6c7574696f6e3d302e303031323231363934353a2c747970653d353a6e616d653d544d44333730325620416d6269656e74204c696768742053656e736f723a76656e646f723d414d533a7265736f6c7574696f6e3d302e30313a2c747970653d363a6e616d653d424d503338302050726573737572652053656e736f723a76656e646f723d426f7363683a7265736f6c7574696f6e3d302e303031373a2c00181607506978656c2034000c161e5175616c636f6d6d546563686e6f6c6f676965732c496e63534d3831353000171606676f6f676c6500081642676f6f676c652f666c616d652f666c616d653a31322f535133412e3232303730352e3030332e41312f383637323232363a757365722f72656c656173652d6b657973000d1606323830302e3000191602313200141601340064160000161600001c1658303130313943314136413442374343414531464633353034383333324630443841374144393037443845324638464439444130354444363931393346363043393039414344303433463037334445363230344341383343360066160130006a1600007316000071160130002c160000231600002a1606476f6f676c6500111600006b163a636f6d2e71712e652e756e696f6e2e64656d6f2e756e696f6e5f3831324544443535363743354431444144444143423944303532323536374331002f16000031160000301610623133343962333662363537316362300100c8163d33322c322c332c342c33362c352c362c34302c3133362c34332c3134332c3134342c31303030322c3131342c31392c31303030332c393939303537323800741600007516013300771607756e6b6e6f776e001a16203664333833313264626565353464613938306339653930363333393565636435002d16000076160b76343b2d315f76363b2d31007816da727778703b2f617065782f636f6d2e616e64726f69642e72756e74696d652f6c696236342f62696f6e69632f6c6962632e736f2c727778703b2f73797374656d2f6c696236342f6c696273656c696e75782e736f2c727778703b2f617065782f636f6d2e616e64726f69642e6172742f6a6176616c69622f61726d36342f626f6f742e6f61742c727778703b2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f2c727778703b2f73797374656d2f6c696236342f6c6962616e64726f69645f72756e74696d652e736f00791600007a1600010087170000074b746d7066733a2f6465763a746d7066733a7277267365636c6162656c266e6f737569642672656c6174696d65266d6f64653d3735352c746d7066733a2f6d6e743a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d373535266769643d313030302c2f6465762f667573653a2f6d6e742f696e7374616c6c65722f302f656d756c617465643a667573653a7277266c617a7974696d65266e6f73756964266e6f646576266e6f65786563266e6f6174696d6526757365725f69643d302667726f75705f69643d3026616c6c6f775f6f746865722c2f646174612f6d656469613a2f6d6e742f696e7374616c6c65722f302f656d756c617465642f302f416e64726f69642f646174613a73646361726466733a7277266e6f73756964266e6f646576266e6f65786563266e6f6174696d652666737569643d313032332666736769643d31303233266769643d31303135266d756c746975736572266d61736b3d36266465726976655f6769642664656661756c745f6e6f726d616c26756e7368617265645f6f62622c2f6465762f626c6f636b2f706c6174666f726d2f736f632f316438343030302e75667368632f62792d6e616d652f706572736973743a2f6d6e742f76656e646f722f706572736973743a657874343a7277267365636c6162656c266e6f73756964266e6f646576266e6f6174696d6526646174613d6f7264657265642c2f6465762f626c6f636b2f62792d6e616d652f6d657461646174613a2f6d657461646174613a657874343a7277267365636c6162656c266e6f73756964266e6f646576266e6f6174696d652664697363617264266e6f64656c616c6c6f6326636f6d6d69743d3126646174613d6a6f75726e616c2c6d616769736b3a2f73797374656d5f6578742f62696e3a746d7066733a726f267365636c6162656c2672656c6174696d65266d6f64653d3735352c6d616769736b3a2f73797374656d5f6578742f62696e2f6d616769736b3a746d7066733a726f267365636c6162656c2672656c6174696d65266d6f64653d3735352c2f6465762f626c6f636b2f626f6f746465766963652f62792d6e616d652f6d6f64656d5f613a2f76656e646f722f6669726d776172655f6d6e743a766661743a726f26636f6e746578743d75236f626a6563745f72236669726d776172655f66696c652373302672656c6174696d65266769643d3130303026666d61736b3d3033333726646d61736b3d3032323726636f6465706167653d34333726696f636861727365743d69736f383835392d312673686f72746e616d653d6c6f776572266572726f72733d72656d6f756e742d726f2c746d7066733a2f617065783a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735352c746d7066733a2f617065782f617065782d696e666f2d6c6973742e786d6c3a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735352c2f6465762f667573653a2f73746f726167652f656d756c617465643a667573653a7277266c617a7974696d65266e6f73756964266e6f646576266e6f65786563266e6f6174696d6526757365725f69643d302667726f75705f69643d3026616c6c6f775f6f746865722c2f646174612f6d656469613a2f73746f726167652f656d756c617465642f302f416e64726f69642f646174613a73646361726466733a7277266e6f73756964266e6f646576266e6f65786563266e6f6174696d652666737569643d313032332666736769643d31303233266769643d31303135266d756c746975736572266d61736b3d36266465726976655f6769642664656661756c745f6e6f726d616c26756e7368617265645f6f62622c746d7066733a2f646174612f646174613a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735312c746d7066733a2f646174612f757365723a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735312c746d7066733a2f646174612f757365725f64653a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735312c746d7066733a2f646174612f6d6973632f70726f66696c65732f6375723a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735312c746d7066733a2f646174612f6d6973632f70726f66696c65732f7265663a746d7066733a7277267365636c6162656c266e6f73756964266e6f646576266e6f657865632672656c6174696d65266d6f64653d3735312c2f6465762f626c6f636b2f6c6f6f703a3a34392c2f6465762f626c6f636b2f646d3a3a31313330007c1600007d167d383133383436353439313334303338333734373a313a313030305f313939325f313031333034385f3432305f33382c323030393838333538323136313432373338323a313a305f355f305f3239325f3635373831312c2d383037383137323635363235383437373231343a313a305f355f305f3239325f363634313235007e160d313735333636383237343833320022161b433a312c543a313735333835343237393632382c4c543a31353334010081170000012d382c776c616e303b36393639393b353b666538303a3a336533363a393632643a626430373a386433663b666430613a613561323a356461393a303a3236653a363566363a643938373a343161613b666430613a613561323a356461393a303a396137663a396636663a626634333a386336393b666430613a613561323a356461393a303a616162393a373832393a623135623a663566323b3139322e3136382e3130302e3131362c725f726d6e65745f64617461303b36353630313b313b666538303a3a646434393a313136313a336233303a3366372c726d6e65745f64617461303b36353630313b313b666538303a3a336430333a643561643a356132303a386463362c64756d6d79303b36353733313b313b666538303a3a653432393a626466663a666563363a333036340100831623302c302ce58685e7bdaee5b18fe5b9952c3130383078323238302c3133312c312c302c01008916af2d3333363536383435373733383439373432363a302c373032363932313832333832303535383031323a756e6c6f636b65642c3537333732363333313637393133313033303a6f72616e67652c2d383233333837303936363033393531333833363a656e666f7263696e672c2d383236383431313634303735373537353431323a302c2d333937303432343431373730363639303338383a312c373234373435303338363538303730353734383a30010085162f616e64726f69642e636f6e74656e742e706d2e495061636b6167654d616e6167657224537475622450726f78792c2c01008c17000001af302c302c2c302c2c66666666666666663a373a3466313a66623a636f6d2e676f6f676c652e616e64726f69642e6d617276696e2e74616c6b6261636b2f2e54616c6b4261636b536572766963653b303a31303a3132303a383a636f6d2e676f6f676c652e616e64726f69642e6d617276696e2e74616c6b6261636b2f636f6d2e676f6f676c652e616e64726f69642e6163636573736962696c6974792e6163636573736962696c6974796d656e752e4163636573736962696c6974794d656e75536572766963653b3430313834313a393a3166313a38393a636f6d2e676f6f676c652e616e64726f69642e6d617276696e2e74616c6b6261636b2f636f6d2e676f6f676c652e616e64726f69642e6163636573736962696c6974792e73656c656374746f737065616b2e53656c656374546f537065616b536572766963653b66666666666666663a66666666666666663a35333a32623a636f6d2e69666c7974656b2e696e7075746d6574686f642f636f6d2e69666c7974656b2e6c69626163636573736962696c6974792e65787465726e616c2e466c79494d454163636573736962696c6974795365727669636501008a1603312c3101008d16073535393638303001009216cb322c3237323439363634302c776c616e302c666538303a3a336533363a393632643a626430373a386433663b666430613a613561323a356461393a303a3236653a363566363a643938373a343161613b666430613a613561323a356461393a303a396137663a396636663a626634333a386336393b3139322e3136382e3130302e3131363b666430613a613561323a356461393a303a616162393a373832393a623135623a663566322c666430613a613561323a356461393a3a313b3139322e3136382e3130302e31303001009317000008f5312c2d343531363332373736373030393037333038303a37313561373736303a2f73797374656d2f6672616d65776f726b2f61726d36342f626f6f742d6672616d65776f726b2e6f61743a464643333032443146333533303541393a722d78703a36343737333a313137382c2d343834343432343433373833393437313831333a366465353030303039303a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a463030423430443131463032343042393a722d78703a313833323a3130382c34343130323731323932333335393738303a366465353030303039303a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a463030423430443131463032343042393a722d78703a313833323a3130382c343335333031373537313832363439363936353a37313630333631303a2f73797374656d2f6672616d65776f726b2f61726d36342f626f6f742d6672616d65776f726b2e6f61743a463030423430443131463032343042393a722d78703a36343737333a313137382c2d343135333033323833323336373432343334343a36666639303838303a2f617065782f636f6d2e616e64726f69642e6172742f6a6176616c69622f61726d36342f626f6f742e6f61743a463030423430443131463032343042393a722d78703a313833323a36332c2d353135313136343637363035373630383033333a37313863323265303a2f73797374656d2f6672616d65776f726b2f61726d36342f626f6f742d6672616d65776f726b2e6f61743a463030423430443131463032343042393a722d78703a36343737333a313137382c3238383135393235333035333433313635343a37313934396339303a2f73797374656d2f6672616d65776f726b2f61726d36342f626f6f742d6672616d65776f726b2e6f61743a323031383430464443303033354644363a722d78703a36343737333a313137382c2d323938303239343037343732363832323039363a366465353030303039303a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a463030423430443131463032343042393a722d78703a313833323a3130382c323535393234343130373531363036363532303a366465353030303039303a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a463030423430443131463032343042393a722d78703a313833323a3130382c343437333334383137333638393232303733323a37313866653438303a2f73797374656d2f6672616d65776f726b2f61726d36342f626f6f742d6672616d65776f726b2e6f61743a463030423430443131463032343042393a722d78703a36343737333a313137382c363836393837303130313332383331323231373a37303135663130303a2f617065782f636f6d2e616e64726f69642e6172742f6a6176616c69622f61726d36342f626f6f742e6f61743a463030423430443131463032343042393a722d78703a313833323a36332c2d333730393637373835333433393435333134383a366465353131646362383a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a464638333034443145383542303046443a722d78703a313833323a3130383a3138333a32623431376532353636663565623638363636363636366236656539353265613a313833323a3130383a464638333034443145383542303046443a2c373139363931363135353532333637383032363a366465353064373562303a2f617065782f636f6d2e616e64726f69642e6172742f6c696236342f6c69626172742e736f3a464638333033443145303037303136443a722d78703a313833323a3130383a3138333a32623431376532353636663565623638363636363636366236656539353265613a313833323a3130383a464638333033443145303037303136443a2c2d333337393937383133393430393139383830393a373037636133366335633a2f617065782f636f6d2e616e64726f69642e72756e74696d652f6c696236342f62696f6e69632f6c6962632e736f3a464643333034443146443742304541393a722d78703a313939323a33383a3138333a63643739353263623430643161326465636136343230633264613739313062653a313939323a33383a464643333034443146443742304541393a2c313930373436313130313431333636383635313a373037636138323735383a2f617065782f636f6d2e616e64726f69642e72756e74696d652f6c696236342f62696f6e69632f6c6962632e736f3a353030303030353830303032314644363a727778703a313939323a33383a3138333a63643739353263623430643161326465636136343230633264613739313062653a313939323a33383a464437424245413946333042303046393a2c363233333937393338303431383235393334393a373039303739353331303a2f73797374656d2f6c696236342f6c696263616d6572615f636c69656e742e736f3a323636424646313745413739464631373a722d78703a36343737333a323035383a3138333a38323665666466613632636533616466316231323263363237356566666330363a36343737333a323035383a323636424646313745413739464631373a2c353635383931383838393235353535303539323a373039306636306135303a2f73797374656d2f6c696236342f6c69626775692e736f3a464634333032443146443742303441393a722d78703a36343737333a323133383a3138333a34663365636538333964303662383731616435323463313062633036623035623a36343737333a323133383a464634333032443146443742303441393a2c2d323439343231333534313435373933323237363a373038643636626634303a2f73797374656d2f6c696236342f6c6962616e64726f69645f72756e74696d652e736f3a464630333032443146443742303241393a722d78703a36343737333a323030353a3138333a63366330336438323535373263393037363134306239663736633635333736363a36343737333a323030353a464630333032443146443742303241393a01009516057a682d434e010096160d417369612f5368616e676861693a0613342e3634302e313531302e3231392c313531301619636f6d2e71712e652e756e696f6e2e64656d6f2e756e696f6e0b5800070003160000081601300009168832333431373533333a38313245444435353637433544314441444441434239443035323235363743313a636f6d2e71712e652e756e696f6e2e64656d6f2e756e696f6e3a342e3634302e313531302e3231393a313531303a313734393630393436313930353a313734393630393436313930353a3935323634373233363a3137343936303934353100071639636f6d2e71712e652e756e696f6e2e64656d6f2e756e696f6e2c31303232382c756e747275737465645f6170702c31303232382c2c696e6974000a1612303133353566353931323538363230383961000c161033353566353931323538363230383961000417000001473133335f302c3133385f302c3134305f322c2d31375f302c3134355f302c3134365f312c3134395f302c32325f352c3135305f302c3135315f312c32345f302c3130305f32332c3130315f33362c3130325f312c3130335f302c3130345f302c3130355f312c3130365f362c3130375f312c34345f302c34375f302c34385f302c3131335f322c34395f302c3131355f342c3131365f312c3131375f312c3131385f312c3132305f31372c3132325f302c73395f312c32315f312c375f302c31305f302c31345f302c33335f302c31315f312c32345f302c31325f302c32335f302c385f302c31335f302c32355f302c32305f302c33355f302c34325f302c3132315f312c3133355f332c3132345f312c3132355f302c3132395f302c3133315f312c3133345f302c3133325f302c3133375f302c3134325f302c3134315f302c3134375f3236680001000216008a060026003c460056000b0b8c980ca80c'
        hexdump(r)
        print(r_hex == ori_hex)
        return body

    def get_third_body(self):
        self.create_third_body()

    def main(self):
        device_info = {
            'first_ts': 1753854279676,
            'platform': '2',
            'version': '90',
            'lc': 'BD4FE23C352252DC',
            'channel': '105498',
            'appid': '1101152570',
            'pkg': 'com.qq.e.union.demo.union',
            'pkgVerInfo': '4.640.1510.219,1510',
            'apiLevel': '32',
            'brand': 'google',
            'model': 'Pixel 4',
            'sign': '6d38312dbee54da980c9e9063395ecd5',
        }
        # self.get_first_body(device_info)
        # self.get_second_body(device_info)
        self.get_third_body()


if __name__ == '__main__':
    M11JceEncrypt().main()

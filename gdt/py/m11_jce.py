# -*- encoding: utf-8 -*-
# @ModuleName: m11_jce
# @Function:
# @Author:
# @Time: 2025/7/30 13:56
from hexdump import hexdump
from gdt.jce_struct import types
from gdt.jce_struct.types import JceStruct, JceField


class StringBytesMapStruct(JceStruct):
    int_0: types.MAP[types.STRING, types.BYTES] = JceField(None, jce_id=0)


# 第一次组包
class DevM2Struct(JceStruct):
    field0: types.ZERO_TAG = JceField(None, jce_id=0)
    field1: types.INT = JceField(None, jce_id=1)
    field2: types.ZERO_TAG = JceField(None, jce_id=2)
    field3: types.MAP = JceField(None, jce_id=3)
    field4: types.MAP = JceField(None, jce_id=4)
    field5: types.ZERO_TAG = JceField(None, jce_id=5)


class DeviceStruct(JceStruct):
    int_0: types.INT64 = JceField(0, jce_id=0)
    map_1: types.MAP[types.STRING, types.STRING] = JceField(None, jce_id=1)
    map_2: DevM2Struct = JceField(None, jce_id=2)
    str_3: types.STRING = JceField('', jce_id=3)


class ReqStruct(JceStruct):
    devs: DeviceStruct = JceField(None, jce_id=0)


class FirstBody(JceStruct):
    int_1: types.INT = JceField(0, jce_id=1)
    int_2: types.INT = JceField(0, jce_id=2)
    int_3: types.INT = JceField(0, jce_id=3)
    int_4: types.INT = JceField(0, jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)
    str_6: types.STRING = JceField('', jce_id=6)
    bytes_7: types.BYTES = JceField(None, jce_id=7)
    int_8: types.INT = JceField(0, jce_id=8)
    map_9: types.MAP = JceField({}, jce_id=9)
    map_10: types.MAP = JceField({}, jce_id=10)


# 第二次组包
class SecondBody(JceStruct):
    int_1: types.INT = JceField(0, jce_id=1)
    int_2: types.INT = JceField(0, jce_id=2)
    int_3: types.INT = JceField(0, jce_id=3)
    int_4: types.INT = JceField(0, jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)
    str_6: types.STRING = JceField('', jce_id=6)
    bytes_7: types.BYTES = JceField(None, jce_id=7)
    int_8: types.INT = JceField(0, jce_id=8)
    map_9: types.MAP = JceField({}, jce_id=9)
    map_10: types.MAP = JceField({}, jce_id=10)


class SecondDev3(JceStruct):
    int_0: types.INT = JceField(0, jce_id=0)
    str_1: types.STRING = JceField('', jce_id=1)
    str_2: types.STRING = JceField('', jce_id=2)
    str_3: types.STRING = JceField('', jce_id=3)
    int_4: types.INT = JceField(None, jce_id=4)


class SecondDev4(JceStruct):
    str_0: types.STRING = JceField('', jce_id=0)
    str_1: types.STRING = JceField('', jce_id=1)


class SecondDev5(JceStruct):
    str_0: types.STRING = JceField('', jce_id=0)
    str_2: types.STRING = JceField('', jce_id=2)
    zero_3: types.ZERO_TAG = JceField(None, jce_id=3)
    str_4: types.STRING = JceField('', jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)


class SecondDeviceStruct(JceStruct):
    int_0: types.INT64 = JceField(0, jce_id=0)
    map_1: types.MAP[types.INT, types.STRING] = JceField(None, jce_id=1)
    zero_2: types.ZERO_TAG = JceField(None, jce_id=2)
    struct_3: SecondDev3 = JceField(None, jce_id=3)
    struct_4: SecondDev4 = JceField(None, jce_id=4)
    struct_5: SecondDev5 = JceField(None, jce_id=5)
    map_6: types.MAP[types.STRING, types.STRING] = JceField(None, jce_id=6)
    map_7: types.MAP[types.STRING, types.STRING] = JceField(None, jce_id=7)
    map_8: types.MAP[types.STRING, types.INT] = JceField(None, jce_id=8)


class SecondReqStruct(JceStruct):
    devs: SecondDeviceStruct = JceField(None, jce_id=0)


# 第三次组包

class ThirdBody(JceStruct):
    int_1: types.INT = JceField(0, jce_id=1)
    int_2: types.INT = JceField(0, jce_id=2)
    int_3: types.INT = JceField(0, jce_id=3)
    int_4: types.INT = JceField(0, jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)
    str_6: types.STRING = JceField('', jce_id=6)
    bytes_7: types.BYTES = JceField(None, jce_id=7)
    int_8: types.INT = JceField(0, jce_id=8)
    map_9: types.MAP = JceField({}, jce_id=9)
    map_10: types.MAP = JceField({}, jce_id=10)


class ThirdDev3(JceStruct):
    str_0: types.STRING = JceField('', jce_id=0)
    str_1: types.STRING = JceField('', jce_id=1)


class ThirdDev5(JceStruct):
    str_0: types.STRING = JceField('', jce_id=0)
    str_2: types.STRING = JceField('', jce_id=2)
    zero_3: types.ZERO_TAG = JceField(None, jce_id=3)
    str_4: types.STRING = JceField('', jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)


class ThirdDev1(JceStruct):
    int_0: types.INT = JceField(0, jce_id=0)
    str_1: types.STRING = JceField('', jce_id=1)
    str_2: types.STRING = JceField('', jce_id=2)
    str_3: types.STRING = JceField('', jce_id=3)
    int_4: types.INT = JceField(None, jce_id=4)


class ThirdDev8(JceStruct):
    str_0: types.STRING = JceField('', jce_id=0)
    str_2: types.STRING = JceField('', jce_id=2)
    zero_3: types.ZERO_TAG = JceField(None, jce_id=3)
    str_4: types.STRING = JceField('', jce_id=4)
    str_5: types.STRING = JceField('', jce_id=5)


class ThirdDeviceStruct(JceStruct):
    int_0: types.INT64 = JceField(0, jce_id=0)
    struct_1: ThirdDev1 = JceField(None, jce_id=1)
    map_2: types.MAP[types.STRING, types.STRING] = JceField(None, jce_id=2)
    struct_3: ThirdDev3 = JceField(None, jce_id=3)
    map_5: types.MAP[types.STRING, types.STRING] = JceField(None, jce_id=5)
    map_6: types.MAP[types.INT, types.STRING] = JceField(None, jce_id=6)
    map_8: ThirdDev8 = JceField(None, jce_id=8)


class ThirdReqStruct(JceStruct):
    devs: ThirdDeviceStruct = JceField(None, jce_id=0)


def create_first_body():
    first_body = FirstBody()

    dev_struct = DeviceStruct()
    dev_struct.int_0 = 1753854279676
    dev_struct.map_1 = {
        types.STRING('platform'): types.STRING('2'),
        types.STRING('version'): types.STRING('90'),
        types.STRING('lc'): types.STRING('BD4FE23C352252DC'),
        types.STRING('channel'): types.STRING('105498'),
        types.STRING('appid'): types.STRING('1101152570'),
        types.STRING('pkg'): types.STRING('com.qq.e.union.demo.union'),
        types.STRING('pkgVerInfo'): types.STRING('4.640.1510.219,1510'),
        types.STRING('apiLevel'): types.STRING('32'),
        types.STRING('brand'): types.STRING('google'),
        types.STRING('model'): types.STRING('Pixel 4'),
    }
    dm2 = DevM2Struct()
    dm2.field0 = types.ZERO_TAG
    dm2.field1 = 1
    dm2.field2 = types.ZERO_TAG
    dm2.field3 = {}
    dm2.field4 = {}
    dm2.field5 = types.ZERO_TAG

    dev_struct.map_2 = dm2
    dev_struct.str_3 = '6d38312dbee54da980c9e9063395ecd5'

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
    # print(r.hex())
    r = bytes.fromhex('00000138') + r
    hexdump(r)
    # print(r.hex())

    # hexdump(bytes_7_value)
    # print(r.hex())


def create_second_body():
    first_body = SecondBody()

    dev_struct = SecondDeviceStruct()
    dev_struct.int_0 = 1753854280152

    dev_data = {
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

    dev_data_6 = {
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
    # print(r.hex())
    # r = bytes.fromhex('00000138') + r
    # print(len(r))
    hexdump(r)
    # print(r.hex())


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


if __name__ == '__main__':
    # create_first_body()
    # create_second_body()
    create_third_body()

# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: params.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='params.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0cparams.proto\"\r\n\x0b\x44\x65\x66\x61ultInfo\"I\n\tM12Params\x12\x1a\n\x08\x61pp_info\x18\x01 \x01(\x0b\x32\x08.AppInfo\x12 \n\x0b\x64\x65vice_info\x18\x02 \x01(\x0b\x32\x0b.DeviceInfo\"\xa0\x02\n\x07\x41ppInfo\x12\x0c\n\x04\x66lag\x18\x01 \x01(\x05\x12\x10\n\x08ts_nonce\x18\x02 \x01(\t\x12\x0e\n\x06status\x18\x03 \x01(\x05\x12\x10\n\x08unknow_1\x18\x04 \x01(\t\x12\x12\n\njs_version\x18\x05 \x01(\t\x12\x13\n\x0bsdk_version\x18\x06 \x01(\t\x12\x12\n\nos_version\x18\x07 \x01(\t\x12\r\n\x05model\x18\x08 \x01(\t\x12$\n\x0e\x64\x65\x66\x61ult_info_1\x18\t \x01(\x0b\x32\x0c.DefaultInfo\x12$\n\x0e\x64\x65\x66\x61ult_info_2\x18\n \x01(\x0b\x32\x0c.DefaultInfo\x12\x14\n\x0cpackage_name\x18\x0b \x01(\t\x12\x0f\n\x07network\x18\x0c \x01(\t\x12\x14\n\x0cnetwork_type\x18\r \x01(\x05\"\xd5\x03\n\nDeviceInfo\x12$\n\x0e\x64\x65\x66\x61ult_info_3\x18\x01 \x01(\x0b\x32\x0c.DefaultInfo\x12\x10\n\x08unknow_2\x18\x02 \x01(\t\x12\x0e\n\x06qm_uin\x18\x03 \x01(\t\x12\r\n\x05\x62rand\x18\x04 \x01(\t\x12\x0e\n\x06k_list\x18\x05 \x01(\t\x12$\n\x0e\x64\x65\x66\x61ult_info_4\x18\x06 \x01(\x0b\x32\x0c.DefaultInfo\x12\x10\n\x08unknow_3\x18\x07 \x01(\t\x12$\n\x0e\x64\x65\x66\x61ult_info_5\x18\x08 \x01(\x0b\x32\x0c.DefaultInfo\x12$\n\x0e\x64\x65\x66\x61ult_info_6\x18\t \x01(\x0b\x32\x0c.DefaultInfo\x12$\n\x0e\x64\x65\x66\x61ult_info_7\x18\n \x01(\x0b\x32\x0c.DefaultInfo\x12$\n\x0e\x64\x65\x66\x61ult_info_8\x18\x0b \x01(\x0b\x32\x0c.DefaultInfo\x12\x13\n\x0bsystem_info\x18\x0c \x01(\t\x12$\n\x0e\x64\x65\x66\x61ult_info_9\x18\r \x01(\x0b\x32\x0c.DefaultInfo\x12\x10\n\x08platform\x18\x0e \x01(\t\x12\n\n\x02ts\x18\x0f \x01(\t\x12%\n\x0f\x64\x65\x66\x61ult_info_10\x18\x10 \x01(\x0b\x32\x0c.DefaultInfo\x12\x10\n\x08unknow_4\x18\x12 \x01(\t'
)




_DEFAULTINFO = _descriptor.Descriptor(
  name='DefaultInfo',
  full_name='DefaultInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=16,
  serialized_end=29,
)


_M12PARAMS = _descriptor.Descriptor(
  name='M12Params',
  full_name='M12Params',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='app_info', full_name='M12Params.app_info', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='device_info', full_name='M12Params.device_info', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=31,
  serialized_end=104,
)


_APPINFO = _descriptor.Descriptor(
  name='AppInfo',
  full_name='AppInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='flag', full_name='AppInfo.flag', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ts_nonce', full_name='AppInfo.ts_nonce', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='status', full_name='AppInfo.status', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknow_1', full_name='AppInfo.unknow_1', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='js_version', full_name='AppInfo.js_version', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='sdk_version', full_name='AppInfo.sdk_version', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='os_version', full_name='AppInfo.os_version', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='model', full_name='AppInfo.model', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_1', full_name='AppInfo.default_info_1', index=8,
      number=9, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_2', full_name='AppInfo.default_info_2', index=9,
      number=10, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='package_name', full_name='AppInfo.package_name', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='network', full_name='AppInfo.network', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='network_type', full_name='AppInfo.network_type', index=12,
      number=13, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=107,
  serialized_end=395,
)


_DEVICEINFO = _descriptor.Descriptor(
  name='DeviceInfo',
  full_name='DeviceInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='default_info_3', full_name='DeviceInfo.default_info_3', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknow_2', full_name='DeviceInfo.unknow_2', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='qm_uin', full_name='DeviceInfo.qm_uin', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='brand', full_name='DeviceInfo.brand', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='k_list', full_name='DeviceInfo.k_list', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_4', full_name='DeviceInfo.default_info_4', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknow_3', full_name='DeviceInfo.unknow_3', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_5', full_name='DeviceInfo.default_info_5', index=7,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_6', full_name='DeviceInfo.default_info_6', index=8,
      number=9, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_7', full_name='DeviceInfo.default_info_7', index=9,
      number=10, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_8', full_name='DeviceInfo.default_info_8', index=10,
      number=11, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='system_info', full_name='DeviceInfo.system_info', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_9', full_name='DeviceInfo.default_info_9', index=12,
      number=13, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='platform', full_name='DeviceInfo.platform', index=13,
      number=14, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ts', full_name='DeviceInfo.ts', index=14,
      number=15, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='default_info_10', full_name='DeviceInfo.default_info_10', index=15,
      number=16, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='unknow_4', full_name='DeviceInfo.unknow_4', index=16,
      number=18, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=398,
  serialized_end=867,
)

_M12PARAMS.fields_by_name['app_info'].message_type = _APPINFO
_M12PARAMS.fields_by_name['device_info'].message_type = _DEVICEINFO
_APPINFO.fields_by_name['default_info_1'].message_type = _DEFAULTINFO
_APPINFO.fields_by_name['default_info_2'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_3'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_4'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_5'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_6'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_7'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_8'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_9'].message_type = _DEFAULTINFO
_DEVICEINFO.fields_by_name['default_info_10'].message_type = _DEFAULTINFO
DESCRIPTOR.message_types_by_name['DefaultInfo'] = _DEFAULTINFO
DESCRIPTOR.message_types_by_name['M12Params'] = _M12PARAMS
DESCRIPTOR.message_types_by_name['AppInfo'] = _APPINFO
DESCRIPTOR.message_types_by_name['DeviceInfo'] = _DEVICEINFO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

DefaultInfo = _reflection.GeneratedProtocolMessageType('DefaultInfo', (_message.Message,), {
  'DESCRIPTOR' : _DEFAULTINFO,
  '__module__' : 'params_pb2'
  # @@protoc_insertion_point(class_scope:DefaultInfo)
  })
_sym_db.RegisterMessage(DefaultInfo)

M12Params = _reflection.GeneratedProtocolMessageType('M12Params', (_message.Message,), {
  'DESCRIPTOR' : _M12PARAMS,
  '__module__' : 'params_pb2'
  # @@protoc_insertion_point(class_scope:M12Params)
  })
_sym_db.RegisterMessage(M12Params)

AppInfo = _reflection.GeneratedProtocolMessageType('AppInfo', (_message.Message,), {
  'DESCRIPTOR' : _APPINFO,
  '__module__' : 'params_pb2'
  # @@protoc_insertion_point(class_scope:AppInfo)
  })
_sym_db.RegisterMessage(AppInfo)

DeviceInfo = _reflection.GeneratedProtocolMessageType('DeviceInfo', (_message.Message,), {
  'DESCRIPTOR' : _DEVICEINFO,
  '__module__' : 'params_pb2'
  # @@protoc_insertion_point(class_scope:DeviceInfo)
  })
_sym_db.RegisterMessage(DeviceInfo)


# @@protoc_insertion_point(module_scope)

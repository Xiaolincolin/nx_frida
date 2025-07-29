from hexdump import hexdump
from jce import JceField, JceStruct, types


class MapStrict(JceStruct):
    key: types.STRING = JceField('', jce_id=0)
    value: types.STRING = JceField('', jce_id=1)


def test_map():
    data = {
        'platform': '2',
        'version': '90',
    }
    result = b''
    for k, v in data.items():
        combined = MapStrict()
        combined.key = k
        combined.value = v
        result += combined.encode()
    hexdump(result)


class ConfigStruct(JceStruct):
    key: types.STRING = JceField('', jce_id=5)
    value: types.STRING = JceField('', jce_id=6)


def test_config():
    data = {
        'getTFConfig': 'getTFConfig'
    }
    result = b''
    for k, v in data.items():
        combined = ConfigStruct()
        combined.key = k
        combined.value = v
        result += combined.encode()
    hexdump(result)


if __name__ == '__main__':
    test_config()

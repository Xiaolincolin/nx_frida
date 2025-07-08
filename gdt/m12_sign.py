import time


def get_now_ts() -> hex:
    ts = int(time.time() * 1000)
    r = hex(ts & 0xFFFFFFFF).replace('0x', '')
    return r


def sign_main():
    sign_tmp = "4c4385107942106ed5898611b4b5c42da1a648ebb7c7ff8cf6820000000000000000"
    sign_start = "4c438510"  # 固定头
    sign_flag = "7942"  # 暂时还不知道
    sign_ts = get_now_ts() # 时间低4字节
    print(sign_ts)


if __name__ == '__main__':
    sign_main()

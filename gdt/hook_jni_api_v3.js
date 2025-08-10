Java.perform(function () {
    const env = Java.vm.getEnv();
    const JV = Process.pointerSize;

    function getSymbol(name) {
        const mod = Process.getModuleByName("libart.so");
        for (const s of mod.enumerateSymbols()) {
            const n = s.name || "";
            if (n.indexOf("art") < 0) continue;
            if (n.indexOf("CheckJNI") >= 0) continue;
            if (n.indexOf("Notify") >= 0) continue;
            if (n.indexOf("mirror") >= 0) continue;
            if (n.indexOf("verifier") >= 0) continue;
            if (n.indexOf("DexFile") >= 0) continue;
            if (n.indexOf("JNIILb1") >= 0) continue;
            if (n.indexOf(name) >= 0) {
                console.log("[getSymbol] hit:", n, "=>", s.address);
                return s.address;
            }
        }
        return null;
    }

    // ===== 小工具 =====
    function toHex(ptr, len, max = 64) {
        if (ptr.isNull() || len.toInt32() <= 0) return '(null)';
        const n = Math.min(len.toInt32(), max);
        const buf = Memory.readByteArray(ptr, n);
        const u8 = new Uint8Array(buf);
        let s = '';
        for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0') + (i + 1 < u8.length ? ' ' : '');
        return s + (len.toInt32() > max ? ' ...' : '') + ` (len=${len})`;
    }

    function jbaToHex(jba, max = 64) {
        try {
            const BA = Java.use('[B');
            const arr = Java.cast(jba, BA);
            const js = Java.array('byte', arr);
            const n = Math.min(js.length, max);
            let out = [];
            for (let i = 0; i < n; i++) {
                let v = js[i];
                if (v < 0) v += 256;
                out.push(v.toString(16).padStart(2, '0'));
            }
            return out.join(' ') + (js.length > max ? ' ...' : '') + ` (len=${js.length})`;
        } catch (_) {
            return '(bad jbyteArray)';
        }
    }

    function hashString(s) {
        let h = 0;
        for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
        return h >>> 0;
    }

    // ===== 记录最近一次 “候选 jstring” =====
    // let lastStrHash = null;
    // const midMap = new Map();

    // const GetMethodID = getSymbol('GetMethodID');
    // if (GetMethodID) {
    //     Interceptor.attach(GetMethodID, {
    //         onEnter(args) {
    //             this.n = Memory.readCString(args[2]);
    //             this.s = Memory.readCString(args[3]);
    //         },
    //         onLeave(rv) {
    //             midMap.set(rv.toString(), {name: this.n, sig: this.s});
    //         }
    //     });
    // }

    // const CallObjectMethodA = getSymbol('CallObjectMethodA');
    // if (CallObjectMethodA) {
    //     Interceptor.attach(CallObjectMethodA, {
    //         onEnter(args) {
    //             this.mid = args[2];
    //             this.info = midMap.get(this.mid.toString());
    //         },
    //         onLeave(rv) {
    //             if (!rv || rv.isNull()) return;
    //             Java.perform(() => {
    //                 // 尝试当作 jstring 读取
    //                 let s = null;
    //                 try {
    //                     s = env.getStringUtfChars(rv).readCString();
    //                 } catch (_) {
    //                 }
    //                 if (!s) return;
    //                 // 这里你可加白名单：只标记来自 JSONObject/JSONArray 的 get/opt 返回
    //                 lastStrHash = hashString(s);
    //                 console.log(`[MARK jstring] hash=${lastStrHash} len=${s.length} head="${s.slice(0, 80)}${s.length > 80 ? '...' : ''}"`);
    //             });
    //         }
    //     });
    // }

    // ===== 1) String -> C 字符串：GetStringUTFChars =====
    // const GetStringUTFChars = getSymbol('GetStringUTFChars');
    // if (GetStringUTFChars) {
    //     Interceptor.attach(GetStringUTFChars, {
    //         onEnter(args) {
    //             this.jstr = args[1];
    //         },
    //         onLeave(rv) {
    //             Java.perform(() => {
    //                 if (!this.jstr || this.jstr.isNull()) return;
    //                 let s = null;
    //                 try {
    //                     s = env.getStringUtfChars(this.jstr).readCString();
    //                 } catch (_) {
    //                 }
    //                 if (!s) return;
    //                 const h = hashString(s);
    //                 if (lastStrHash !== null && h === lastStrHash) {
    //                     console.log(`[JNI GetStringUTFChars] hit marked string hash=${h} len=${s.length}`);
    //                     console.log(`  text.head="${s.slice(0, 80)}${s.length > 80 ? '...' : ''}"`);
    //                 }
    //             });
    //         }
    //     });
    // }

    // ===== 2) C 缓冲区 -> jbyteArray：SetByteArrayRegion / Elements / Critical =====
    // 2.1 SetByteArrayRegion(env, jbyteArray, start, len, buf)
    const SetByteArrayRegion = getSymbol('SetByteArrayRegion');
    if (SetByteArrayRegion) {
        Interceptor.attach(SetByteArrayRegion, {
            onEnter(args) {
                const jba = args[1];
                const start = args[2];
                const len = args[3];
                const buf = args[4];
                console.log(`[JNI SetByteArrayRegion] start=${start} len=${len}`);
                console.log('  src ' + toHex(buf, len));
                // 打印目标数组整体（可能只是一段），尽量少读
                try {
                    console.log('  dst ' + jbaToHex(jba));
                } catch (_) {
                }
            }
        });
    }

    // 2.2 GetByteArrayElements / ReleaseByteArrayElements
    // const jbaMap = new Map(); // nativePtr -> {jba, len}
    // const GetByteArrayElements = getSymbol('GetByteArrayElements');
    // const ReleaseByteArrayElements = getSymbol('ReleaseByteArrayElements');
    // if (GetByteArrayElements) {
    //     Interceptor.attach(GetByteArrayElements, {
    //         onEnter(args) {
    //             this.jba = args[1];
    //         },
    //         onLeave(rv) {
    //             try {
    //                 const len = env.getArrayLength(this.jba);
    //                 jbaMap.set(rv.toString(), {jba: this.jba, len: ptr(len)});
    //                 console.log(`[JNI GetByteArrayElements] jba=${this.jba} ptr=${rv} len=${len}`);
    //             } catch (_) {
    //             }
    //         }
    //     });
    // }
    // if (ReleaseByteArrayElements) {
    //     Interceptor.attach(ReleaseByteArrayElements, {
    //         onEnter(args) {
    //             const jba = args[1];
    //             const ptrNative = args[2];
    //             const info = jbaMap.get(ptrNative.toString());
    //             if (info) {
    //                 console.log(`[JNI ReleaseByteArrayElements] jba=${jba} ptr=${ptrNative}`);
    //                 console.log('  buf ' + toHex(ptrNative, info.len));
    //                 jbaMap.delete(ptrNative.toString());
    //             }
    //         }
    //     });
    // }

    // 2.3 Get/ReleasePrimitiveArrayCritical：有些库走这条
    // const critMap = new Map();
    // const GetPrimitiveArrayCritical = getSymbol('GetPrimitiveArrayCritical');
    // const ReleasePrimitiveArrayCritical = getSymbol('ReleasePrimitiveArrayCritical');
    // if (GetPrimitiveArrayCritical) {
    //     Interceptor.attach(GetPrimitiveArrayCritical, {
    //         onEnter(args) {
    //             this.arr = args[1];
    //         },
    //         onLeave(rv) {
    //             try {
    //                 const len = env.getArrayLength(this.arr);
    //                 critMap.set(rv.toString(), {arr: this.arr, len: ptr(len)});
    //                 console.log(`[JNI GetPrimitiveArrayCritical] arr=${this.arr} ptr=${rv} len=${len}`);
    //             } catch (_) {
    //             }
    //         }
    //     });
    // }
    // if (ReleasePrimitiveArrayCritical) {
    //     Interceptor.attach(ReleasePrimitiveArrayCritical, {
    //         onEnter(args) {
    //             const arr = args[1];
    //             const ptrNative = args[2];
    //             const info = critMap.get(ptrNative.toString());
    //             if (info) {
    //                 console.log(`[JNI ReleasePrimitiveArrayCritical] arr=${arr} ptr=${ptrNative}`);
    //                 console.log('  buf ' + toHex(ptrNative, info.len));
    //                 critMap.delete(ptrNative.toString());
    //             }
    //         }
    //     });
    // }

    // ===== 3) NewByteArray / NewDirectByteBuffer（观察分配 & 直接缓冲区） =====
    // const NewByteArray = getSymbol('NewByteArray');
    // if (NewByteArray) {
    //     Interceptor.attach(NewByteArray, {
    //         onEnter(args) {
    //             this.len = args[1];
    //         },
    //         onLeave(rv) {
    //             console.log(`[JNI NewByteArray] len=${this.len} => jba=${rv}`);
    //         }
    //     });
    // }
    // const NewDirectByteBuffer = getSymbol('NewDirectByteBuffer');
    // if (NewDirectByteBuffer) {
    //     Interceptor.attach(NewDirectByteBuffer, {
    //         onEnter(args) {
    //             this.addr = args[1];
    //             this.len = args[2];
    //         },
    //         onLeave(rv) {
    //             console.log(`[JNI NewDirectByteBuffer] ptr=${this.addr} len=${this.len} => obj=${rv}`);
    //             console.log('  buf ' + toHex(this.addr, this.len));
    //         }
    //     });
    // }

});

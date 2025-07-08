// frida_trace_v48_delay.js
'use strict';

const SO_NAME   = "libgdtqone.so";   // ⚠️改成你的 so
const FUNCOFF   = 0x43BDC;          // ⚠️sub_43BDC 起始偏移
const WAIT_MS   = 1000;             // 1 秒 = 1000 ms

/* ---------------------------------------------------------- *
 *  真正的 Hook 逻辑函数 —— 包在方法里，稍后用 setTimeout 调用  *
 * ---------------------------------------------------------- */
function doHook() {
    console.log(`💡 doHook() fired at ${new Date().toLocaleTimeString()}`);

    // 如果是 Java Hook 放到 Java.perform 里
    // Java.perform(() => { ... });

    /* -------- Native Trace  -------- */
    const base = Module.findBaseAddress(SO_NAME);
    if (!base) {
        console.error(`[!] Can't find ${SO_NAME}`);
        return;
    }
    const funcAddr = base.add(FUNCOFF);

    /* 保存执行过的 v48 值 */
    const visited = new Set();

    Interceptor.attach(funcAddr, {
        onEnter(args) {
            this.sp = this.context.sp;     // sp 定住，onLeave 读栈上的 v48
        },
        onLeave(retval) {
            const v48 = Memory.readS32(this.sp.add(0x324));  // v48 偏移
            if (!visited.has(v48)) {
                visited.add(v48);
                console.log(`📌 v48 hit: ${v48}`);
            }
        }
    });

    /* 10 秒后导出日志并打印统计 */
    setTimeout(() => {
        console.log(`✅ trace done, total unique states = ${visited.size}`);
        visited.forEach(v => console.log("state:", v));
    }, 10000);
}

/* ----------------- 延迟 1 秒启动 ----------------- */
setTimeout(doHook, WAIT_MS);
/* ------------------------------------------------ */

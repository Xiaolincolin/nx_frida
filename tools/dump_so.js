function dump_so() {
    // 设置目标 so 名称
    let so_name = "libyaqpro.3e364a2a.so";

    Java.perform(function () {
        try {
            let currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            let dir = currentApplication.getApplicationContext().getFilesDir().getPath();

            let libso = Process.getModuleByName(so_name);
            console.log("[name]:", libso.name);
            console.log("[base]:", libso.base);
            console.log("[size]:", libso.size);
            console.log("[path]:", libso.path);

            let file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
            let file_handle = new File(file_path, "wb");

            if (file_handle) {
                Memory.protect(ptr(libso.base), libso.size, "rwx"); // 或 "r" 视情况而定
                let libso_buffer = ptr(libso.base).readByteArray(libso.size);
                file_handle.write(libso_buffer);
                file_handle.flush();
                file_handle.close();
                console.log("[dump]", file_path);
            }
        } catch (e) {
            console.error("[error]", e);
        }
    });

}

setImmediate(dump_so);
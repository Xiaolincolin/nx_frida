function hook_java() {
    Java.perform(function() {
        var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
        dexclassLoader.loadClass.overload('java.lang.String').implementation = function(name){
            var hookname = "com.bytedance.sdk.openadsdk.core.AdSdkInitializerHolder";
            var result = this.loadClass(name,false);
            // console.log("dexclassLoader: " + name);
            if(name==hookname) {
                Java.enumerateClassLoaders({
                    onMatch: function (loader) {
                        try {
                            if (loader.findClass("ms.bz.bd.c.Pgl.pblb")) {
                            // if (loader.findClass("com.bytedance.sdk.component.panglearmor.SoftDecTool")) {
                                Java.classFactory.loader = loader;      //切换classloader
                                hook()
                                // call_getO()
                            }

                        } catch (error) {
                            // console.log("222222222222");
                        }
                    }, onComplete: function () {
                    }
                });
            }
            return result;
        }
    });
}

function tryGetClass(className) {
    let clz = undefined;
    try {
        clz = Java.use(className);
    } catch (e) {
    }
    return clz;
}

function newMethodBeat(text, executor) {
    let threadClz = Java.use("java.lang.Thread");
    let androidLogClz = Java.use("android.util.Log");
    let exceptionClz = Java.use("java.lang.Exception");
    let currentThread = threadClz.currentThread();
    let beat = {};
    beat.invokeId = Math.random().toString(36).slice(-8);
    beat.executor = executor;
    beat.threadId = currentThread.getId();
    beat.threadName = currentThread.getName();
    beat.text = text;
    beat.startTime = new Date().getTime();
    beat.stackInfo = androidLogClz.getStackTraceString(exceptionClz.$new()).substring(20);
    return beat;
}

function printBeat(beat) {
    let str = ("------------startFlag:" + beat.invokeId + ",objectHash:" + beat.executor + ",thread(id:" + beat.threadId + ",name:" + beat.threadName + "),timestamp:" + beat.startTime + "---------------\n");
    str += beat.text + "\n";
    str += beat.stackInfo;
    str += ("------------endFlag:" + beat.invokeId + ",usedtime:" + (new Date().getTime() - beat.startTime) + "---------------\n");
    console.log(str);
}

let containRegExps = new Array()

let notContainRegExps = new Array(RegExp(/\.jpg/), RegExp(/\.png/))

function check(str) {
    str = str.toString();
    if (!(str && str.match)) {
        return false;
    }
    for (let i = 0; i < containRegExps.length; i++) {
        if (!str.match(containRegExps[i])) {
            return false;
        }
    }
    for (let i = 0; i < notContainRegExps.length; i++) {
        if (str.match(notContainRegExps[i])) {
            return false;
        }
    }
    return true;
}

Java.perform(function () {
    let uriParseClz = Java.use('java.net.URI');
    let uriParseClzConstruct = uriParseClz.$init.overload("java.lang.String");
    uriParseClzConstruct.implementation = function (url) {
        let result = uriParseClzConstruct.call(this, url);
        let executor = this.hashCode();
        let beatText = "url:" + url + "\npublic java.net.URI(String)";
        let beat = newMethodBeat(beatText, executor);
        if (check(url)) {
            printBeat(beat);
        }
        return result;
    };

    // URL
    let URLClz = Java.use('java.net.URL');
    let androidLogClz = Java.use("android.util.Log");
    let exceptionClz = Java.use("java.lang.Exception");
    let urlConstruct = URLClz.$init.overload("java.lang.String");
    urlConstruct.implementation = function (url) {
        let result = urlConstruct.call(this, url);
        let executor = this.hashCode();
        let beatText = "url:" + url + "\npublic java.net.URL(String)";
        let beat = newMethodBeat(beatText, executor);
        if (check(url)) {
            printBeat(beat);
        }
        return result;
    };

    //ok系统原生支持
    let sysBuilderClz = tryGetClass('com.android.okhttp.Request$Builder');
    if (sysBuilderClz) {
        sysBuilderClz.build.implementation = function () {
            let okRequestResult = this.build();
            let httpUrl = okRequestResult.url();
            let url = httpUrl.toString();
            let executor = this.hashCode();
            let beatText = "url:" + url + "\ncom.android.okhttp.Request.Builder.build()";
            let beat = newMethodBeat(beatText, executor);
            if (check(url)) {
                printBeat(beat);
            }
            return okRequestResult
        };
    }

    //ok本地依赖
    let builderClz = tryGetClass('okhttp3.Request$Builder');
    if (builderClz) {
        let buildFunc = builderClz.build.overload();
        buildFunc.implementation = function () {
            let okRequestResult = buildFunc.call(this);
            let httpUrl = okRequestResult.url();
            let url = httpUrl.toString();
            let executor = this.hashCode();
            let beatText = "url:" + url + "\nokhttp3.Request.Builder.build()";
            let beat = newMethodBeat(beatText, executor);
            if (check(url)) {
                printBeat(beat);
            }
            return okRequestResult
        };
    }

    let android_net_Uri_clz = Java.use('android.net.Uri');
    let android_net_Uri_clz_method_parse_u5rj = android_net_Uri_clz.parse.overload('java.lang.String');
    android_net_Uri_clz_method_parse_u5rj.implementation = function (url) {
        let executor = 'Class';
        let beatText = url + '\npublic static android.net.Uri android.net.Uri.parse(java.lang.String)';
        let beat = newMethodBeat(beatText, executor);
        let ret = android_net_Uri_clz_method_parse_u5rj.call(android_net_Uri_clz, url);
        if (check(url)) {
            printBeat(beat);
        }
        return ret;
    };
});

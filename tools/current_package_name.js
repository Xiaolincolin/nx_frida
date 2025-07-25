Java.perform(function () {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var currentPackageName = ActivityThread.currentPackageName();
    console.log("当前前台应用包名: " + currentPackageName);
});

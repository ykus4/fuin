package com.fuin.stub

import android.app.Application
import android.content.Context
import android.util.Log

private const val TAG = "ApplicationSwap"

/**
 * Replaces the running Application instance with the original app's Application class
 * using reflection on Android internals.
 *
 * This technique works on AOSP up to API 33. Higher APIs may require additional
 * compatibility handling if internal field names change.
 */
object ApplicationSwap {

    fun swap(stub: Application, originalClass: Class<out Application>) {
        val original = originalClass.newInstance()

        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val currentActivityThread = activityThreadClass
            .getMethod("currentActivityThread")
            .invoke(null)

        patchField(activityThreadClass, currentActivityThread, "mInitialApplication", original)

        val allApps = activityThreadClass
            .getDeclaredField("mAllApplications")
            .also { it.isAccessible = true }
            .get(currentActivityThread) as MutableList<Application>

        allApps.remove(stub)
        allApps.add(original)

        val packages = activityThreadClass.getDeclaredField("mPackages")
            .also { it.isAccessible = true }
            .get(currentActivityThread) as Map<*, *>
        val appRef = packages[stub.packageName]
        if (appRef != null) {
            val loadedApk = Class.forName("java.lang.ref.WeakReference")
                .getMethod("get")
                .invoke(appRef)
            if (loadedApk != null) {
                patchField(loadedApk.javaClass, loadedApk, "mApplication", original)
            }
        }

        Application::class.java.getDeclaredMethod("attach", Context::class.java)
            .also { it.isAccessible = true }
            .invoke(original, stub.baseContext)

        original.onCreate()
    }

    private fun patchField(clazz: Class<*>, target: Any, fieldName: String, value: Any) {
        try {
            clazz.getDeclaredField(fieldName).also {
                it.isAccessible = true
                it.set(target, value)
            }
        } catch (e: NoSuchFieldException) {
            Log.w(TAG, "Field '$fieldName' not found in ${clazz.name} — skipping (API version difference?)")
        }
    }
}

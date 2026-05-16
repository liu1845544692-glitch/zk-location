/*
 * 文件功能：
 * - 封装 Android GNSS 单次定位读取。
 * - 只负责从系统 LocationManager 获取 WGS84 经纬度，不参与 proof 或签名。
 *
 * 执行流程：
 * 1. 调用 hasFineLocationPermission 检查精确定位权限。
 * 2. requestSingleFix 检查 GPS provider 是否开启。
 * 3. 注册 LocationListener 等待一次 GNSS 结果。
 * 4. 收到定位或超时后移除 listener，并通过回调返回结果。
 */
package com.example.moproapp

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat

object GnssLocationReader {
    // GNSS_TIMEOUT_MS：单次定位最长等待时间，避免 UI 一直处于 locating 状态。
    private const val GNSS_TIMEOUT_MS = 30_000L

    /** 检查 App 是否已经获得 ACCESS_FINE_LOCATION 权限。 */
    fun hasFineLocationPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
    }

    /** 请求一次 GPS/GNSS 定位，成功和失败都只回调一次。 */
    @SuppressLint("MissingPermission")
    fun requestSingleFix(
        context: Context,
        onLocation: (Location) -> Unit,
        onError: (String) -> Unit
    ) {
        if (!hasFineLocationPermission(context)) {
            onError("Fine location permission is not granted")
            return
        }

        // locationManager：系统定位服务，用于检查 GPS provider 和注册 listener。
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        if (!locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
            onError("GNSS provider is disabled")
            return
        }

        // mainHandler：主线程 Handler，用于设置超时回调。
        val mainHandler = Handler(Looper.getMainLooper())
        // completed：防止定位、超时、provider disabled 多路径重复回调。
        var completed = false

        // listener：LocationManager 更新回调，finish 中需要引用它来移除监听。
        lateinit var listener: LocationListener
        // finish：统一收尾函数，保证移除 listener、取消超时并只返回一次结果。
        fun finish(location: Location?, error: String?) {
            if (completed) return
            completed = true
            locationManager.removeUpdates(listener)
            mainHandler.removeCallbacksAndMessages(listener)
            if (location != null) {
                onLocation(location)
            } else {
                onError(error ?: "GNSS location failed")
            }
        }

        listener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                finish(location, null)
            }

            override fun onProviderDisabled(provider: String) {
                if (provider == LocationManager.GPS_PROVIDER) {
                    finish(null, "GNSS provider was disabled")
                }
            }

            @Deprecated("Deprecated by Android framework")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit
        }

        locationManager.requestLocationUpdates(
            LocationManager.GPS_PROVIDER,
            0L,
            0f,
            listener,
            Looper.getMainLooper()
        )

        mainHandler.postAtTime(
            { finish(null, "GNSS timeout after ${GNSS_TIMEOUT_MS / 1000}s") },
            listener,
            android.os.SystemClock.uptimeMillis() + GNSS_TIMEOUT_MS
        )
    }
}

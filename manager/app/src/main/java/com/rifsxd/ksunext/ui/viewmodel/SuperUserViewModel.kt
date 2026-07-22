package com.rifsxd.ksunext.ui.viewmodel

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.os.Parcelable
import android.os.SystemClock
import kotlinx.parcelize.Parcelize
import android.util.Log
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import android.graphics.drawable.Drawable
import androidx.lifecycle.ViewModel
import com.rifsxd.ksunext.Natives
import com.rifsxd.ksunext.ksuApp
import com.rifsxd.ksunext.ui.util.HanziToPinyin
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.Collator
import java.util.*

class SuperUserViewModel : ViewModel() {

    companion object {
        private const val TAG = "SuperUserViewModel"
         var apps by mutableStateOf<List<AppInfo>>(emptyList())

        @JvmStatic
        fun getAppIconDrawable(context: Context, packageName: String): Drawable? {
            val appDetail = apps.find { it.packageName == packageName }
            return appDetail?.packageInfo?.applicationInfo?.loadIcon(context.packageManager)
        }
        private var profileOverrides by mutableStateOf<Map<String, Natives.Profile>>(emptyMap())
    }

    @Parcelize
    data class AppInfo(
        val label: String,
        val packageInfo: PackageInfo,
        val profile: Natives.Profile?,
    ) : Parcelable {
        val packageName: String
            get() = packageInfo.packageName
        val uid: Int
            get() = packageInfo.applicationInfo!!.uid

        val allowSu: Boolean
            get() = profile != null && profile.allowSu
        val hasCustomProfile: Boolean
            get() {
                if (profile == null) {
                    return false
                }

                return if (profile.allowSu) {
                    !profile.rootUseDefault
                } else {
                    !profile.nonRootUseDefault
                }
            }
    }

    private val prefs = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)!!
    private val mutex = Mutex()

    var search by mutableStateOf("")
    var showSystemApps by mutableStateOf(prefs.getBoolean("show_system_apps", false))
        private set
    var isRefreshing by mutableStateOf(false)
        private set

    fun updateShowSystemApps(newValue: Boolean) {
        showSystemApps = newValue
        prefs.edit { putBoolean("show_system_apps", newValue) }
    }

    private val sortedList by derivedStateOf {
        val comparator = compareBy<AppInfo> {
            when {
                it.profile != null && it.profile.allowSu -> 0
                it.profile != null && (
                    if (it.profile.allowSu) !it.profile.rootUseDefault else !it.profile.nonRootUseDefault
                ) -> 1
                else -> 2
            }
        }.then(compareBy(Collator.getInstance(Locale.getDefault()), AppInfo::label))
        apps.sortedWith(comparator).also {
            isRefreshing = false
        }
    }

    val appList by derivedStateOf {
        sortedList.map { app ->
            profileOverrides[app.packageName]?.let { app.copy(profile = it) } ?: app
        }.filter {
            it.label.contains(search, true) || it.packageName.contains(
                search,
                true
            ) || HanziToPinyin.getInstance()
                .toPinyinString(it.label).contains(search, true)
        }.filter {
            it.uid == 2000 // Always show shell
                    || showSystemApps || it.packageInfo.applicationInfo!!.flags.and(ApplicationInfo.FLAG_SYSTEM) == 0
        }
    }

    fun updateAppProfile(packageName: String, newProfile: Natives.Profile) {
        profileOverrides = profileOverrides.toMutableMap().apply {
            put(packageName, newProfile)
        }
    }


    suspend fun fetchAppList() {
        mutex.withLock {
            isRefreshing = true
            try {
                withContext(Dispatchers.IO) {
                    val pm = ksuApp.packageManager
                    val start = SystemClock.elapsedRealtime()

                    val allPackages = pm.getInstalledPackages(0)
                    Log.i(TAG, "all packages: ${allPackages.size}")

                    apps = allPackages.map {
                        val appInfo = it.applicationInfo!!
                        val uid = appInfo.uid
                        val profile = Natives.getAppProfile(it.packageName, uid)
                        AppInfo(
                            label = appInfo.loadLabel(pm).toString(),
                            packageInfo = it,
                            profile = profile,
                        )
                    }
                    Log.i(TAG, "load cost: ${SystemClock.elapsedRealtime() - start}")
                    Log.i(TAG, "apps total: ${apps.size}")
                }
            } catch (e: Exception) {
                Log.w(TAG, "fetchAppList failed", e)
                isRefreshing = false
            }
        }
    }
}


package com.rifsxd.ksunext.ui.util

import android.content.Context
import androidx.core.content.edit

/**
 * GitHub raw content proxy helper.
 * Stores user's selected proxy URL in SharedPreferences and provides
 * URL construction for module repository and meta module endpoints.
 */
object ProxyHelper {
    private const val PREFS_NAME = "proxy_config"
    private const val KEY_SELECTED = "selected_proxy"

    /** Default: no proxy, use raw.githubusercontent.com directly. */
    const val DEFAULT_PROXY = "https://raw.githubusercontent.com/"

    /** All available proxy options. */
    val PROXY_LIST = listOf(
        DEFAULT_PROXY,
        "https://ghfast.top/",
        "https://ghproxy.net/",
        "https://gh-proxy.com/",
    )

    /** Test URL for speed measurement (modules.json, ~6416 bytes). */
    const val SPEED_TEST_PATH =
        "KernelSU-Next/KernelSU-Next-Modules-Repo/refs/heads/main/modules.json"

    /** Full test URL for speed testing: proxy_prefix + raw_url. */
    fun speedTestUrl(proxy: String): String {
        return if (proxy == DEFAULT_PROXY) {
            "${DEFAULT_PROXY}${SPEED_TEST_PATH}"
        } else {
            "${proxy}https://raw.githubusercontent.com/${SPEED_TEST_PATH}"
        }
    }

    /** Get the currently selected proxy (defaults to DEFAULT_PROXY). */
    fun getSelectedProxy(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_SELECTED, DEFAULT_PROXY) ?: DEFAULT_PROXY
    }

    /** Save the selected proxy. */
    fun setSelectedProxy(context: Context, proxy: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit { putString(KEY_SELECTED, proxy) }
    }

    /**
     * Build the final URL by prepending the selected proxy.
     * If the default proxy is selected, the original URL is returned unchanged.
     *
     * Example:
     *   selected = "https://ghfast.top/"
     *   url      = "https://raw.githubusercontent.com/.../modules.json"
     *   result   = "https://ghfast.top/https://raw.githubusercontent.com/.../modules.json"
     */
    fun buildUrl(context: Context, rawUrl: String): String {
        val proxy = getSelectedProxy(context)
        return if (proxy == DEFAULT_PROXY) rawUrl else "$proxy$rawUrl"
    }
}

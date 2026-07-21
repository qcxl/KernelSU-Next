package com.rifsxd.ksunext.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.rifsxd.ksunext.R
import com.rifsxd.ksunext.ui.util.ProxyHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Proxy configuration page.
 * User can select a GitHub raw content proxy and test speed of each option.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun ProxyConfigScreen(navigator: DestinationsNavigator) {
    val context = LocalContext.current
    val selectedProxy = remember { mutableStateOf(ProxyHelper.getSelectedProxy(context)) }

    val speedResults = remember { mutableStateMapOf<String, Long>() }
    val isTesting = remember { mutableStateOf(false) }

    suspend fun runSpeedTest() {
        isTesting.value = true
        val results = withContext(Dispatchers.IO) {
            ProxyHelper.PROXY_LIST.map { proxy ->
                async { proxy to testSpeed(proxy) }
            }.awaitAll()
        }
        results.forEach { (proxy, speed) -> speedResults[proxy] = speed }
        isTesting.value = false
    }

    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.proxy_config),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Black,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    TextButton(
                        onClick = {
                            if (!isTesting.value) {
                                scope.launch { runSpeedTest() }
                            }
                        },
                        enabled = !isTesting.value
                    ) {
                        Icon(Icons.Filled.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            if (isTesting.value) stringResource(R.string.proxy_testing)
                            else stringResource(R.string.proxy_speed_test)
                        )
                    }
                },
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal
                ),
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp)
        ) {
            itemsIndexed(ProxyHelper.PROXY_LIST) { _, proxy ->
                val isSelected = proxy == selectedProxy.value
                val speed = speedResults[proxy]
                val speedText = when {
                    speed == null || speed == 0L -> null
                    speed == -1L -> stringResource(R.string.proxy_speed_failed)
                    else -> "${speed}ms"
                }

                ListItem(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            selectedProxy.value = proxy
                            ProxyHelper.setSelectedProxy(context, proxy)
                        },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    headlineContent = {
                        Text(
                            text = proxy,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    supportingContent = {
                        if (speedText != null) {
                            Text(
                                text = speedText,
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (speed == -1L)
                                    MaterialTheme.colorScheme.error
                                else
                                    MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                    trailingContent = {
                        if (isSelected) {
                            Icon(
                                Icons.Filled.Check,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                )
            }
        }
    }
}

/** Test a single proxy's speed by fetching modules.json. Returns elapsed ms or -1 on error. */
private suspend fun testSpeed(proxy: String): Long {
    return withContext(Dispatchers.IO) {
        val url = ProxyHelper.speedTestUrl(proxy)
        val start = System.currentTimeMillis()
        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("User-Agent", "KernelSU-Next-ProxyTest")
            val code = conn.responseCode
            if (code != 200) {
                conn.disconnect()
                return@withContext -1L
            }
            conn.inputStream.use { it.readBytes() }
            conn.disconnect()
            System.currentTimeMillis() - start
        } catch (_: Exception) {
            -1L
        }
    }
}

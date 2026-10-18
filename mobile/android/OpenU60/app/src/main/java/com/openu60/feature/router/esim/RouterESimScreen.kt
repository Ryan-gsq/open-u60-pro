package com.openu60.feature.router.esim

import android.text.format.Formatter
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.openu60.core.model.RouterESimChip
import com.openu60.core.model.RouterESimConnectionPhase
import com.openu60.core.model.RouterESimProfile

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RouterESimScreen(onBack: () -> Unit, viewModel: RouterESimViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsState()
    var adding by remember { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(viewModel) { viewModel.refresh() }
    DisposableEffect(lifecycleOwner, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) viewModel.startMonitoring()
            if (event == Lifecycle.Event.ON_STOP) viewModel.stopMonitoring()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) viewModel.startMonitoring()
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer); viewModel.stopMonitoring() }
    }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("eSIM Profiles") },
            navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = {
                IconButton(onClick = { viewModel.resetDownloadResult(); adding = true }, enabled = !state.blocksSwitching) { Icon(Icons.Default.Add, "Add eSIM") }
                IconButton(onClick = viewModel::refresh, enabled = !state.isLoading && !state.isSwitching && !state.operationInFlight) {
                    if (state.isLoading) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    else Icon(Icons.Default.Refresh, if (state.download.isBusy) "Refresh download status" else "Refresh profiles and connection")
                }
            },
        )
    }) { padding ->
        PullToRefreshBox(
            isRefreshing = state.isLoading && state.hasLoaded,
            onRefresh = viewModel::refresh,
            modifier = Modifier.padding(padding).fillMaxSize(),
        ) {
            RouterESimContent(state, viewModel::refresh, viewModel::requestSwitch, viewModel::requestDelete, { viewModel.resetDownloadResult(); adding = true }, { adding = true })
        }
    }

    if (adding) RouterESimAddScreen(viewModel) { adding = false }
    state.pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = viewModel::dismissDelete,
            icon = { Icon(Icons.Default.DeleteForever, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Delete ${target.displayName} permanently?") },
            text = { Text("This can’t be undone. You’d need a new QR code from ${target.provider.ifEmpty { target.displayName }} to get this eSIM back.") },
            confirmButton = { TextButton(onClick = viewModel::confirmDelete, enabled = !state.blocksSwitching) { Text("Delete profile", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = viewModel::dismissDelete) { Text("Cancel") } },
        )
    }
    state.pendingSwitch?.let { target ->
        AlertDialog(
            onDismissRequest = viewModel::dismissSwitch,
            icon = { Icon(Icons.Default.SwapHoriz, null) },
            title = { Text("Switch to ${target.displayName}?") },
            text = {
                Text("The router disconnects from ${state.enabledProfile?.displayName ?: "the current profile"} and connects with ${target.displayName}. Internet is down for about a minute. Wi-Fi stays on.")
            },
            confirmButton = { TextButton(onClick = viewModel::confirmSwitch) { Text("Switch to ${target.displayName}") } },
            dismissButton = { TextButton(onClick = viewModel::dismissSwitch) { Text("Cancel") } },
        )
    }
}

@Composable
private fun RouterESimContent(state: RouterESimState, refresh: () -> Unit, switch: (RouterESimProfile) -> Unit, delete: (RouterESimProfile) -> Unit = {}, add: () -> Unit = {}, resume: () -> Unit = {}) {
    val others = remember(state.profiles) { state.profiles.filter { !it.isEnabled } }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        if (!state.hasLoaded && state.profiles.isEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(24.dp), horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Reading profiles", style = MaterialTheme.typography.titleMedium)
                        Text("Checking the eSIM in your router…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        } else {
            state.message?.let { message ->
                MessageCard(message, state.messageIsError, !state.blocksSwitching, refresh)
            }
            if (state.download.state != "idle") {
                Card(onClick = resume, modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Downloading, null, tint = MaterialTheme.colorScheme.primary)
                        Column(Modifier.weight(1f)) {
                            Text(state.download.progressText, style = MaterialTheme.typography.titleSmall)
                            Text("Tap to view progress and next steps", style = MaterialTheme.typography.bodySmall)
                        }
                        Icon(Icons.Default.ChevronRight, null)
                    }
                }
            }
            if (state.profiles.isEmpty()) {
                if (state.message == null && !state.download.isBusy) {
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.fillMaxWidth().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
                            Icon(Icons.Default.SimCard, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text("No profiles yet", style = MaterialTheme.typography.titleMedium)
                            Text("Add one with the QR code from your operator.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Button(onClick = add, enabled = !state.blocksSwitching) { Text("Add eSIM") }
                        }
                    }
                }
            } else {
                state.enabledProfile?.let { active ->
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        SectionHeading("Active profile")
                        ProfileCard(active, false) {}
                    }
                }
                ConnectionCard(state, refresh)
                if (others.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            SectionHeading(if (state.enabledProfile == null) "Profiles on this card" else "Other profiles")
                            Text(others.size.toString(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        others.forEach { profile ->
                            key(profile.iccid) { ProfileCard(profile, !state.blocksSwitching, onDelete = { delete(profile) }) { switch(profile) } }
                        }
                    }
                }
                OutlinedButton(onClick = add, enabled = !state.blocksSwitching, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.AddCircle, null); Spacer(Modifier.width(8.dp)); Text("Add eSIM")
                }
                Surface(color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.45f), shape = RoundedCornerShape(12.dp)) {
                    Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Icon(Icons.Default.Schedule, null, tint = MaterialTheme.colorScheme.onTertiaryContainer)
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text("Switching pauses internet", style = MaterialTheme.typography.titleSmall)
                            Text("About a minute offline. Your router’s Wi-Fi stays on.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            if (state.chip != RouterESimChip.empty) ChipCard(state.chip)
        }
    }
}

@Composable
private fun SectionHeading(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.semantics { heading() })
}

@Composable
private fun ProfileCard(profile: RouterESimProfile, canSwitch: Boolean, onDelete: (() -> Unit)? = null, onSwitch: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    val accent = if (profile.isEnabled) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.primary
    val subtitle = when {
        profile.provider.isNotEmpty() && !profile.provider.equals(profile.displayName, true) -> profile.provider
        profile.name.isNotEmpty() && !profile.name.equals(profile.displayName, true) -> profile.name
        profile.isEnabled -> "Active on your eSIM card"
        else -> "Stored on your eSIM card"
    }
    val shape = RoundedCornerShape(16.dp)
    val colors = CardDefaults.cardColors(containerColor = if (profile.isEnabled) accent.copy(alpha = 0.08f) else MaterialTheme.colorScheme.surfaceContainerLow)
    val border = BorderStroke(1.dp, if (profile.isEnabled) accent.copy(alpha = 0.35f) else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
    val content: @Composable () -> Unit = {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(46.dp, 50.dp).background(accent.copy(alpha = 0.1f), RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                Icon(Icons.Default.SimCard, null, tint = accent)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(profile.displayName.ifEmpty { "Unnamed profile" }, style = if (profile.isEnabled) MaterialTheme.typography.titleLarge else MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("Profile · …${profile.iccid.takeLast(4)}", style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            when {
                profile.isEnabled -> {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        Icon(Icons.Default.CheckCircle, null, Modifier.size(16.dp), tint = accent)
                        Text("Active", style = MaterialTheme.typography.labelMedium, color = accent)
                    }
                }
                profile.canEnable -> Box(Modifier.size(36.dp).background(accent.copy(alpha = if (canSwitch) 0.1f else 0.03f), CircleShape), contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.SwapHoriz, "Switch profile", tint = if (canSwitch) accent else MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(20.dp))
                }
                else -> Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Icon(Icons.Default.Lock, null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
                    Text("Unavailable", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (!profile.isEnabled && onDelete != null) {
                Box {
                    IconButton(onClick = { menu = true }, enabled = canSwitch) { Icon(Icons.Default.MoreVert, "Profile options for ${profile.displayName}") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(text = { Text("Delete profile", color = MaterialTheme.colorScheme.error) },
                            leadingIcon = { Icon(Icons.Default.DeleteOutline, null) }, onClick = { menu = false; onDelete() }, enabled = canSwitch)
                    }
                }
            }
        }
    }
    if (profile.canEnable) {
        Card(onClick = onSwitch, enabled = canSwitch, modifier = Modifier.fillMaxWidth(), shape = shape, colors = colors, border = border) { content() }
    } else {
        Card(modifier = Modifier.fillMaxWidth(), shape = shape, colors = colors, border = border) { content() }
    }
}

@Composable
private fun ConnectionCard(state: RouterESimState, refresh: () -> Unit) {
    val phase = state.connectionPhase
    val progress = phase.blocksSwitching
    val title = when (phase) {
        RouterESimConnectionPhase.CHECKING -> "Checking connection"
        RouterESimConnectionPhase.SWITCHING -> "Switching to ${state.switchingTo ?: "profile"}"
        RouterESimConnectionPhase.RELOADING -> "Reloading SIM"
        RouterESimConnectionPhase.REGISTERING -> "Registering on network"
        RouterESimConnectionPhase.CONNECTED -> "Mobile internet connected"
        RouterESimConnectionPhase.DISCONNECTED -> "Mobile internet offline"
        RouterESimConnectionPhase.WAITING -> "Still waiting for internet"
        RouterESimConnectionPhase.UNAVAILABLE -> "Connection status unavailable"
    }
    val detail = state.connectionNote ?: when (phase) {
        RouterESimConnectionPhase.SWITCHING, RouterESimConnectionPhase.RELOADING, RouterESimConnectionPhase.REGISTERING -> "Internet usually returns in about a minute. Wi-Fi stays on."
        RouterESimConnectionPhase.WAITING -> "The profile is active. First network registration can take longer."
        RouterESimConnectionPhase.DISCONNECTED -> "Mobile data is not connected. Your router’s Wi-Fi stays on."
        RouterESimConnectionPhase.CHECKING -> "Reading live status from your router."
        RouterESimConnectionPhase.UNAVAILABLE -> "Refresh to check the router’s mobile data connection."
        RouterESimConnectionPhase.CONNECTED -> listOf(state.operatorName, state.networkType).filter { it.isNotEmpty() }.joinToString(" · ")
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.Top) {
                if (progress || phase == RouterESimConnectionPhase.CHECKING) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                else Icon(if (phase == RouterESimConnectionPhase.CONNECTED) Icons.Default.CheckCircle else Icons.Default.SignalCellularConnectedNoInternet0Bar, null, tint = if (phase == RouterESimConnectionPhase.CONNECTED) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    if (detail.isNotEmpty()) Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (phase == RouterESimConnectionPhase.CONNECTED) Row(horizontalArrangement = Arrangement.spacedBy(2.dp), verticalAlignment = Alignment.Bottom) {
                    repeat(5) { index ->
                        Box(Modifier.width(3.dp).height((6 + index * 2).dp).background(
                            if (index < state.signalBars) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.2f),
                            RoundedCornerShape(1.dp),
                        ))
                    }
                }
            }
            if (state.switchingTo != null && (progress || phase == RouterESimConnectionPhase.CONNECTED || phase == RouterESimConnectionPhase.WAITING)) {
                val current = when (phase) { RouterESimConnectionPhase.SWITCHING -> 0; RouterESimConnectionPhase.RELOADING -> 1; else -> 2 }
                Column(Modifier.padding(start = 32.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    listOf("Switch profile", "Reload SIM", "Connect to network").forEachIndexed { index, label ->
                        val complete = phase == RouterESimConnectionPhase.CONNECTED || index < current
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(if (complete) Icons.Default.CheckCircle else if (index == current) Icons.Default.RadioButtonChecked else Icons.Default.RadioButtonUnchecked, null, Modifier.size(15.dp), tint = if (complete) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            if (phase == RouterESimConnectionPhase.WAITING || phase == RouterESimConnectionPhase.UNAVAILABLE) OutlinedButton(onClick = refresh) { Text("Check again") }
        }
    }
}

@Composable
private fun MessageCard(message: String, isError: Boolean, canRetry: Boolean, retry: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(if (isError) Icons.Default.ErrorOutline else Icons.Default.CheckCircle, null, tint = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary)
                Text(if (message.contains("busy", true)) "Card is busy" else if (isError) "Couldn’t complete the request" else "Profile updated", style = MaterialTheme.typography.titleSmall)
            }
            Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (isError) OutlinedButton(onClick = retry, enabled = canRetry) { Text("Try again") }
        }
    }
}

@Composable
private fun ChipCard(chip: RouterESimChip) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    // Revealed identifiers intentionally do not survive screen recreation or backgrounding.
    var revealed by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_STOP) { revealed = false; copied = false } }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Surface(onClick = { expanded = !expanded; if (!expanded) { revealed = false; copied = false } }, color = Color.Transparent) {
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(Icons.Default.SimCard, null, tint = MaterialTheme.colorScheme.primary)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text("eSIM card", style = MaterialTheme.typography.titleSmall)
                        Text("Card details & identifiers", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Icon(if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, if (expanded) "Collapse card details" else "Expand card details", modifier = Modifier.size(20.dp))
                }
            }
            if (expanded) {
                HorizontalDivider()
                if (chip.firmware.isNotEmpty()) InfoRow("Firmware", chip.firmware)
                chip.freeMemoryBytes?.let { InfoRow("Free memory", Formatter.formatShortFileSize(context, it.coerceAtLeast(0))) }
                if (chip.eid.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.PrivacyTip, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text("EID", Modifier.weight(1f).padding(start = 6.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            IconButton(onClick = { revealed = !revealed; copied = false }) { Icon(if (revealed) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (revealed) "Hide EID" else "Reveal EID") }
                            if (revealed) IconButton(onClick = { clipboard.setText(AnnotatedString(chip.eid)); copied = true }) { Icon(if (copied) Icons.Default.Check else Icons.Default.ContentCopy, if (copied) "EID copied" else "Copy EID") }
                        }
                        Text(if (revealed) chip.eid else "•••• •••• •••• …${chip.eid.takeLast(4)}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

@Preview(showBackground = true)
@Composable
private fun ProfilesPreview() {
    MaterialTheme {
        RouterESimContent(RouterESimState(
            hasLoaded = true, connectionPhase = RouterESimConnectionPhase.CONNECTED, operatorName = "Smart", networkType = "5G NSA", signalBars = 4,
            profiles = listOf(
                RouterESimProfile("8963000000000000001", provider = "SMART", nickname = "Smart", isEnabled = true, profileClass = "operational"),
                RouterESimProfile("8963000000000000002", provider = "GOMO", name = "Globe Philippines ODC", profileClass = "operational"),
                RouterESimProfile("8963000000000000003", provider = "DITO", name = "DITO", profileClass = "operational"),
            ), chip = RouterESimChip("89000000000000000000000000000001", "4.2.0", 972020),
        ), {}, {})
    }
}

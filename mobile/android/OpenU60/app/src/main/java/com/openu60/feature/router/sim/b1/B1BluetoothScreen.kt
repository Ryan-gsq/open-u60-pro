package com.openu60.feature.router.sim.b1

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openu60.core.bluetooth.AndroidB1BluetoothTransport
import com.openu60.core.bluetooth.B1ConnectionPhase

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun B1BluetoothScreen(onBack: () -> Unit, viewModel: B1BluetoothViewModel = viewModel()) {
    val controller = viewModel.controller
    val state by controller.state.collectAsState()
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var permissionMessage by remember { mutableStateOf<String?>(null) }
    var awaitingPermission by remember { mutableStateOf(false) }
    val permissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        if (awaitingPermission) {
            awaitingPermission = false
            if (AndroidB1BluetoothTransport.hasPermissions(context) &&
                lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                permissionMessage = null
                controller.scan()
            } else {
                permissionMessage = "Allow Nearby devices and precise location access in Settings, then scan again."
            }
        }
    }

    DisposableEffect(lifecycleOwner, controller) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                awaitingPermission = false
                controller.disconnect()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            awaitingPermission = false
            controller.disconnect()
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text("9eSIM B1 Bluetooth") }, navigationIcon = {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
        })
    }) { padding ->
        LazyColumn(modifier = Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(state.phase.title, style = MaterialTheme.typography.titleMedium)
                        state.selectedDevice?.let { Text(it.displayName) }
                        (permissionMessage ?: state.message)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                        if (state.phase.canScan) {
                            Button(onClick = {
                                if (AndroidB1BluetoothTransport.hasPermissions(context)) {
                                    permissionMessage = null
                                    controller.scan()
                                } else {
                                    awaitingPermission = true
                                    permissions.launch(AndroidB1BluetoothTransport.requiredPermissions())
                                }
                            }, enabled = !awaitingPermission) { Text("Scan nearby devices") }
                        }
                        if (state.phase == B1ConnectionPhase.SCANNING || state.phase == B1ConnectionPhase.PREPARING) {
                            OutlinedButton(onClick = controller::stopScan) { Text("Stop scan") }
                        }
                        if (!state.phase.canScan) {
                            OutlinedButton(onClick = controller::disconnect) { Text("Disconnect / cancel") }
                        }
                    }
                }
            }
            item {
                Text("Nearby BLE devices", style = MaterialTheme.typography.titleMedium)
                Text("Select your B1. Device names and service identifiers alone do not verify B1 support.",
                    style = MaterialTheme.typography.bodySmall)
            }
            items(state.devices, key = { it.id }) { device ->
                OutlinedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(device.displayName, style = MaterialTheme.typography.titleSmall)
                        Text(device.id, style = MaterialTheme.typography.bodySmall)
                        device.rssi?.let { Text("Signal: $it dBm", style = MaterialTheme.typography.bodySmall) }
                        Button(onClick = { controller.connect(device) },
                            enabled = state.phase.canConnect && device.connectable != false) {
                            Text(if (device.connectable == false) "Not connectable" else "Connect")
                        }
                    }
                }
            }
            state.snapshot?.let { snapshot ->
                item {
                    Text("Observed GATT services", style = MaterialTheme.typography.titleMedium)
                    Text("Captured for ${snapshot.device.displayName} at ${snapshot.observedAt}.",
                        style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = {
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, snapshot.evidenceJSON())
                            putExtra(Intent.EXTRA_SUBJECT, "OpenU60 B1 GATT observations")
                        }
                        context.startActivity(Intent.createChooser(intent, "Share GATT report"))
                    }) { Text("Share GATT report") }
                }
                items(snapshot.services, key = { it.instance }) { service ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Service ${service.uuid}", style = MaterialTheme.typography.bodySmall)
                            service.characteristics.forEach { characteristic ->
                                Text(characteristic.uuid, style = MaterialTheme.typography.bodySmall)
                                Text(characteristic.properties.joinToString(", "), style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
            item {
                B1ESimManagementPanel(viewModel)
            }
        }
    }
}

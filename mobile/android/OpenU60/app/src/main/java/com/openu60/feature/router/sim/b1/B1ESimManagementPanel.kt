package com.openu60.feature.router.sim.b1

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.openu60.core.esim.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun B1ESimManagementPanel(viewModel: B1BluetoothViewModel) {
    val controller = viewModel.management
    val state by controller.state.collectAsState()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var adding by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<B1ESimProfile?>(null) }
    var removing by remember { mutableStateOf<B1ESimProfile?>(null) }
    var activationCode by remember { mutableStateOf("") }
    var confirmationCode by remember { mutableStateOf("") }
    var nickname by remember { mutableStateOf("") }
    var inputError by remember { mutableStateOf<String?>(null) }
    var exportMessage by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<B1ExportArtifact?>(null) }
    LaunchedEffect(state.card?.eid) {
        adding = false; renaming = null; removing = null
        activationCode = ""; confirmationCode = ""
    }

    val saveExport: (android.net.Uri?) -> Unit = { uri ->
        val artifact = pendingExport
        pendingExport = null
        if (uri != null && artifact != null) {
            scope.launch {
                exportMessage = try {
                    withContext(Dispatchers.IO) {
                        val output = context.contentResolver.openOutputStream(uri) ?: error("No export destination")
                        output.use { it.write(artifact.data) }
                    }
                    "Export saved."
                } catch (_: Exception) { "Export could not be saved." }
            }
        }
    }
    val saveMetadata = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json"), saveExport)
    val saveTransfer = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream"), saveExport)

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("eSIM management", style = MaterialTheme.typography.titleMedium)
        state.card?.let { Text("EID: ${it.eid}", style = MaterialTheme.typography.bodySmall) }
        if (state.phase == B1ManagementPhase.OPENING || state.phase == B1ManagementPhase.BUSY) LinearProgressIndicator(Modifier.fillMaxWidth())
        state.message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        state.journalWarning?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        if (state.phase == B1ManagementPhase.DISCONNECTED) Text("Connect to your B1 to read its eSIM profiles.", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { scope.launch { controller.refresh() } }, enabled = state.canRefresh) { Text("Refresh profile list") }
        OutlinedButton(onClick = { adding = true; inputError = null },
            enabled = state.supports(B1ESimAction.DOWNLOAD) && state.journalWarning == null) { Text("Add eSIM") }
        OutlinedButton(onClick = {
            try {
                val artifact = controller.exportMetadata()
                pendingExport = artifact
                saveMetadata.launch(artifact.filename)
            } catch (_: Exception) { exportMessage = "Connect and refresh profiles before exporting metadata." }
        }, enabled = state.canOperate) { Text("Export profile metadata") }
        exportMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

        Text("Installed profiles", style = MaterialTheme.typography.titleMedium)
        if (state.canOperate && state.profiles.isEmpty()) Text("No profiles are installed on this card.")
        state.profiles.forEach { profile ->
            key(profile.iccid) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(profile.displayName, style = MaterialTheme.typography.titleSmall)
                        Text(profile.iccid, style = MaterialTheme.typography.bodySmall)
                        profile.provider?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                        Text(profile.state.name.lowercase(), style = MaterialTheme.typography.labelMedium)
                        Button(onClick = { scope.launch { controller.enable(profile.iccid) } },
                            enabled = state.supports(B1ESimAction.ENABLE) && profile.state != B1ProfileState.ENABLED) {
                            Text(if (profile.state == B1ProfileState.ENABLED) "Already active" else "Use this profile")
                        }
                        OutlinedButton(onClick = { scope.launch { controller.disable(profile.iccid) } },
                            enabled = state.supports(B1ESimAction.DISABLE) && profile.canDisable != false && profile.state != B1ProfileState.DISABLED) { Text("Disable profile") }
                        OutlinedButton(onClick = { renaming = profile; nickname = profile.nickname ?: "" },
                            enabled = state.supports(B1ESimAction.RENAME)) { Text("Rename profile") }
                        OutlinedButton(onClick = { removing = profile },
                            enabled = state.supports(B1ESimAction.DELETE) && profile.canDelete != false) { Text("Remove profile") }
                        OutlinedButton(onClick = {
                            scope.launch {
                                controller.exportTransfer(profile.iccid)?.let { artifact ->
                                    pendingExport = artifact
                                    saveTransfer.launch(artifact.filename)
                                }
                            }
                        }, enabled = state.supports(B1ESimAction.EXPORT_TRANSFER)) { Text("Export transfer package") }
                    }
                }
            }
        }
        Text("Metadata export contains profile details. Transfer-package export requires explicit support from the card adapter.",
            style = MaterialTheme.typography.bodySmall)
        if (state.pendingNotifications.isNotEmpty()) {
            Text("Pending download notifications", style = MaterialTheme.typography.titleMedium)
            Text("${state.notificationsForCard.size} pending for this card; ${state.pendingNotifications.size} retained in total.",
                style = MaterialTheme.typography.bodySmall)
            Text("Reconnect the matching card to complete server notifications. Installed profiles will not be downloaded again.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { scope.launch { controller.retryNotifications() } },
                enabled = state.supports(B1ESimAction.NOTIFY) && state.notificationsForCard.isNotEmpty()) { Text("Complete pending notifications") }
        }
    }

    if (adding) AlertDialog(
        onDismissRequest = { adding = false; activationCode = ""; confirmationCode = "" },
        title = { Text("Add eSIM") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = activationCode, onValueChange = { activationCode = it }, label = { Text("LPA:1$ activation code") },
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii))
                OutlinedTextField(value = confirmationCode, onValueChange = { confirmationCode = it },
                    label = { Text("Confirmation code (if required)") }, visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password))
                Text("Provisioning credentials remain in memory and are excluded from profile exports.", style = MaterialTheme.typography.bodySmall)
                inputError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                try {
                    val request = B1DownloadRequest(activationCode, confirmationCode)
                    activationCode = ""; confirmationCode = ""; adding = false
                    scope.launch { controller.download(request) }
                } catch (error: B1ESimError) { inputError = error.message }
            }, enabled = activationCode.isNotBlank() && state.supports(B1ESimAction.DOWNLOAD)) { Text("Download") }
        },
        dismissButton = { TextButton(onClick = { adding = false; activationCode = ""; confirmationCode = "" }) { Text("Cancel") } },
    )
    renaming?.let { profile ->
        AlertDialog(onDismissRequest = { renaming = null }, title = { Text("Rename profile") },
            text = { OutlinedTextField(value = nickname, onValueChange = { nickname = it }, label = { Text("Nickname") }) },
            confirmButton = { TextButton(onClick = { val requestedName = nickname; renaming = null; scope.launch { controller.rename(profile.iccid, requestedName) } },
                enabled = nickname.isNotBlank() && state.supports(B1ESimAction.RENAME)) { Text("Save") } },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } })
    }
    removing?.let { profile ->
        AlertDialog(onDismissRequest = { removing = null }, title = { Text("Remove eSIM profile?") },
            text = { Text("Remove ${profile.displayName}? This can interrupt router service. You may need a new activation code to install it again.") },
            confirmButton = { TextButton(onClick = { removing = null; scope.launch { controller.delete(profile.iccid) } },
                enabled = state.supports(B1ESimAction.DELETE)) { Text("Remove") } },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } })
    }
}

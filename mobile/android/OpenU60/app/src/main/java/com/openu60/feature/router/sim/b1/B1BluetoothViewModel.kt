package com.openu60.feature.router.sim.b1

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openu60.core.bluetooth.B1ConnectionPhase
import com.openu60.core.bluetooth.AndroidB1BluetoothTransport
import com.openu60.core.bluetooth.B1BluetoothController
import com.openu60.core.esim.B1ESimController
import com.openu60.core.esim.B1PreferencesNotificationStore
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class B1BluetoothViewModel(application: Application) : AndroidViewModel(application) {
    val controller = B1BluetoothController(viewModelScope, { AndroidB1BluetoothTransport(application) })
    val management = B1ESimController(B1PreferencesNotificationStore(application))
    init {
        viewModelScope.launch {
            controller.state.map { Triple(it.sessionGeneration, it.phase, it.snapshot) }.distinctUntilChanged().collectLatest { (_, phase, snapshot) ->
                if (phase == B1ConnectionPhase.CONNECTED_UNVERIFIED && snapshot != null) management.attach(snapshot)
                else management.disconnect()
            }
        }
    }
    override fun onCleared() { management.disconnect(); controller.disconnect() }
}

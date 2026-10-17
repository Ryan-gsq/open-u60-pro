package com.openu60.core.bluetooth

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import androidx.core.location.LocationManagerCompat
import java.time.Instant

/** Discovery only: no characteristic reads/writes, guessed bonding or initialization. */
@SuppressLint("MissingPermission") // Checked before use; revocation is handled as a session failure.
class AndroidB1BluetoothTransport(private val context: Context) : B1BluetoothTransport {
    override var onEvent: ((B1BluetoothEvent) -> Unit)? = null
    private val handler = Handler(Looper.getMainLooper())
    private val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
    private val devices = mutableMapOf<String, android.bluetooth.BluetoothDevice>()
    private val observations = mutableMapOf<String, B1NearbyDevice>()
    private var scanner: BluetoothLeScanner? = null
    private var gatt: BluetoothGatt? = null
    private var scanning = false
    private var closed = false
    private var receiverRegistered = false

    companion object {
        // Avoid neverForLocation filtering while the B1 advertising contract is unknown.
        fun requiredPermissions(): Array<String> = if (Build.VERSION.SDK_INT >= 31) arrayOf(
            Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION,
        ) else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

        fun hasPermissions(context: Context) = requiredPermissions().all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        }
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (closed || intent.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            checked {
                if (adapter?.isEnabled != true) emit(B1BluetoothEvent.Failure("Bluetooth turned off. Enable it and scan again."))
            }
        }
    }

    override fun startScan() {
        if (closed) return
        if (!hasPermissions(context)) {
            emit(B1BluetoothEvent.Failure("Allow Nearby devices and location access to scan for the B1."))
            return
        }
        checked {
            if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) || adapter == null) {
                emit(B1BluetoothEvent.Failure("Bluetooth Low Energy is unavailable on this device."))
                return@checked
            }
            if (!adapter.isEnabled) {
                emit(B1BluetoothEvent.Failure("Turn on Bluetooth in Settings and scan again."))
                return@checked
            }
            val locationManager = context.getSystemService(LocationManager::class.java)
            if (Build.VERSION.SDK_INT < 31 && locationManager != null && !LocationManagerCompat.isLocationEnabled(locationManager)) {
                emit(B1BluetoothEvent.Failure("Enable location services to scan on this Android version."))
                return@checked
            }
            ContextCompat.registerReceiver(context, receiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
                ContextCompat.RECEIVER_EXPORTED)
            receiverRegistered = true
            scanner = adapter.bluetoothLeScanner
            if (scanner == null) {
                emit(B1BluetoothEvent.Failure("Bluetooth scanner is unavailable. Try again."))
                return@checked
            }
            scanning = true
            scanner?.startScan(null, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), scanCallback)
            emit(B1BluetoothEvent.Scanning)
        }
    }

    override fun stopScan() {
        val wasScanning = scanning
        scanning = false
        if (wasScanning) {
            try { scanner?.stopScan(scanCallback) } catch (_: SecurityException) { /* Revoked permission; session cleanup continues. */ }
        }
    }

    override fun connect(deviceID: String) {
        if (closed) return
        checked {
            val device = devices[deviceID]
            if (device == null || adapter?.isEnabled != true) {
                emit(B1BluetoothEvent.Failure("Device is no longer available. Scan again."))
                return@checked
            }
            stopScan()
            gatt = device.connectGatt(context, false, gattCallback, android.bluetooth.BluetoothDevice.TRANSPORT_LE)
            if (gatt == null) emit(B1BluetoothEvent.Failure("Could not start the Bluetooth connection."))
        }
    }

    override fun close() {
        closed = true
        onEvent = null
        stopScan()
        val previous = gatt
        gatt = null
        try { previous?.disconnect() } catch (_: SecurityException) { /* Release the GATT client even after permission revocation. */ }
        try { previous?.close() } catch (_: SecurityException) { /* Client is already retired from this session. */ }
        if (receiverRegistered) {
            context.unregisterReceiver(receiver)
            receiverRegistered = false
        }
        scanner = null
        devices.clear()
        observations.clear()
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            handler.post {
                if (closed || !scanning) return@post
                checked {
                    val id = result.device.address
                    if (id !in devices && devices.size >= 100) return@checked
                    val device = B1NearbyDevice(id, result.scanRecord?.deviceName ?: result.device.name,
                        result.rssi.takeUnless { it == 127 }, result.isConnectable,
                        result.scanRecord?.serviceUuids?.map { it.uuid.toString() } ?: emptyList())
                    devices[id] = result.device
                    observations[id] = device
                    emit(B1BluetoothEvent.Discovered(device))
                }
            }
        }

        override fun onScanFailed(errorCode: Int) {
            handler.post {
                if (!closed && scanning) emit(B1BluetoothEvent.Failure("Bluetooth scan failed (code $errorCode). Try again."))
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(source: BluetoothGatt, status: Int, newState: Int) {
            handler.post {
                if (closed || source !== gatt) return@post
                checked {
                    when {
                        status != BluetoothGatt.GATT_SUCCESS -> emit(B1BluetoothEvent.Failure("Bluetooth connection failed (code $status). Scan again."))
                        newState == BluetoothProfile.STATE_CONNECTED -> {
                            emit(B1BluetoothEvent.Connected)
                            if (!source.discoverServices()) emit(B1BluetoothEvent.Failure("Could not start GATT discovery."))
                        }
                        newState == BluetoothProfile.STATE_DISCONNECTED -> emit(B1BluetoothEvent.Disconnected)
                    }
                }
            }
        }

        override fun onServicesDiscovered(source: BluetoothGatt, status: Int) {
            handler.post {
                if (closed || source !== gatt) return@post
                checked {
                    if (status != BluetoothGatt.GATT_SUCCESS || source.services.isEmpty()) {
                        emit(B1BluetoothEvent.Failure("GATT services could not be discovered. Scan again."))
                        return@checked
                    }
                    val device = observations[source.device.address] ?: return@checked
                    val services = source.services.mapIndexed { index, service ->
                        B1GattService(index, service.uuid.toString(), service.characteristics.mapIndexed { index, characteristic ->
                            B1GattCharacteristic(index, characteristic.uuid.toString(), properties(characteristic.properties))
                        })
                    }
                    // No MTU request is needed for discovery. Unknown sizes remain null.
                    emit(B1BluetoothEvent.GattDiscovered(B1GattSnapshot(device, services, observedAt = Instant.now().toString())))
                }
            }
        }

        override fun onServiceChanged(source: BluetoothGatt) {
            handler.post {
                if (!closed && source === gatt) emit(B1BluetoothEvent.Failure("GATT services changed. Scan again to rediscover the device."))
            }
        }
    }

    private fun emit(event: B1BluetoothEvent) { if (!closed) onEvent?.invoke(event) }

    private inline fun checked(block: () -> Unit) {
        try { block() }
        catch (_: SecurityException) { emit(B1BluetoothEvent.Failure("Bluetooth permission was denied or revoked. Allow access in Settings.")) }
        catch (_: IllegalStateException) { emit(B1BluetoothEvent.Failure("Bluetooth became unavailable. Enable it and scan again.")) }
    }

    private fun properties(value: Int): List<String> = listOf(
        BluetoothGattCharacteristic.PROPERTY_READ to "read", BluetoothGattCharacteristic.PROPERTY_WRITE to "write",
        BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE to "writeWithoutResponse",
        BluetoothGattCharacteristic.PROPERTY_NOTIFY to "notify", BluetoothGattCharacteristic.PROPERTY_INDICATE to "indicate",
        BluetoothGattCharacteristic.PROPERTY_BROADCAST to "broadcast", BluetoothGattCharacteristic.PROPERTY_SIGNED_WRITE to "signedWrite",
        BluetoothGattCharacteristic.PROPERTY_EXTENDED_PROPS to "extended",
    ).filter { value and it.first != 0 }.map { it.second }
}

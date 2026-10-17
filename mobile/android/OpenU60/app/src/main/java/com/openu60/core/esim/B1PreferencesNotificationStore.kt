package com.openu60.core.esim

import android.content.Context
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class B1PreferencesNotificationStore(context: Context) : B1NotificationStore {
    private val preferences = context.getSharedPreferences("b1_notifications", Context.MODE_PRIVATE)
    override fun load(): List<B1PendingNotification> = preferences.getString("pending.v1", null)?.let {
        Json.decodeFromString<List<B1PendingNotification>>(it)
    } ?: emptyList()
    override fun save(items: List<B1PendingNotification>) {
        // Persist only card/notification identifiers; activation and confirmation codes are excluded.
        if (!preferences.edit().putString("pending.v1", Json.encodeToString(items)).commit()) {
            throw B1ESimError.JournalUnavailable
        }
    }
}

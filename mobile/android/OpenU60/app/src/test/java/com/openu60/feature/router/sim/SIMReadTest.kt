package com.openu60.feature.router.sim

import com.openu60.core.network.AgentError
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SIMReadTest {
    @Test
    fun aFailedReadReachesTheRefreshCatchInsteadOfCancellingItsLaunch() = runBlocking {
        // Like viewModelScope: a SupervisorJob with no handler of its own (this one only records
        // what would reach the thread's uncaught handler and kill the app).
        val uncaught = mutableListOf<Throwable>()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e -> uncaught += e })
        var caught: Throwable? = null
        val refresh = scope.launch {
            try {
                SIMViewModel.read { path ->
                    // The modem reloads the SIM: the lock-trials read fails while SIM info is pending.
                    if (path == SIMViewModel.LOCK_TRIALS_PATH) throw AgentError.ServerError("ubus call failed")
                    delay(100)
                    emptyMap()
                }
            } catch (e: Exception) {
                caught = e
            }
        }
        refresh.join()
        assertTrue("the refresh's own catch sees the read error, got $caught", caught is AgentError.ServerError)
        assertFalse("the refresh launch ends normally", refresh.isCancelled)
        assertTrue("nothing reaches the uncaught handler: $uncaught", uncaught.isEmpty())
    }

    @Test
    fun readsSimInfoAndTheRoutedLockTrials() = runBlocking {
        val paths = mutableListOf<String>()
        SIMViewModel.read { path -> paths += path; emptyMap() }
        assertEquals(setOf("/api/sim/info", "/api/sim/lock-trials"), paths.toSet())
    }
}

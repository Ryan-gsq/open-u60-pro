package com.openu60.core.model

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SimIdentityTrackerTest {
    private fun stamp(instance: Long = 1760860000000, epoch: Long = 0, phase: String = "idle") =
        Json.parseToJsonElement("""{"sim_iccid":"89630000000000000027","agent_instance":$instance,"sim_epoch":$epoch,"sim_phase":"$phase"}""").jsonObject

    @Test
    fun firstSightingSeedsAndRepeatsAreNoChange() {
        val tracker = SimIdentityTracker()
        assertFalse("the first sighting only seeds", tracker.observe(stamp()))
        assertFalse(tracker.observe(stamp()))
    }

    @Test
    fun phaseEpochAndInstanceChangesAreSeen() {
        val tracker = SimIdentityTracker()
        tracker.observe(stamp())
        assertTrue(tracker.observe(stamp(phase = "leaving")))
        assertTrue(tracker.observe(stamp(epoch = 1, phase = "leaving")))
        assertTrue(tracker.observe(stamp(epoch = 1, phase = "changed")))
        assertFalse(tracker.observe(stamp(epoch = 1, phase = "changed")))
        assertTrue(tracker.observe(stamp(epoch = 1, phase = "online")))
        assertTrue("a restarted agent starts again at 0", tracker.observe(stamp(instance = 1760870000000, epoch = 0)))
    }

    @Test
    fun lateRepliesAndUnstampedPayloadsAreIgnored() {
        val tracker = SimIdentityTracker()
        tracker.observe(stamp(epoch = 2, phase = "online"))
        assertFalse("a lower epoch in the same run is a late reply", tracker.observe(stamp(epoch = 1, phase = "changed")))
        assertFalse("the late reply did not replace the last stamp", tracker.observe(stamp(epoch = 2, phase = "online")))
        val old = Json.parseToJsonElement("""{"sim_iccid":"89630000000000000027","sim_states":"ready"}""").jsonObject
        assertFalse("older agents send no stamp", tracker.observe(old))
        assertFalse(tracker.observe(stamp(epoch = 2, phase = "online")))
        val partial = Json.parseToJsonElement("""{"agent_instance":1760860000000,"sim_epoch":3}""").jsonObject
        assertFalse(tracker.observe(partial))
        assertNull(SimIdentity.from(partial))
        assertNull("quoted numbers are not a stamp",
            SimIdentity.from(Json.parseToJsonElement("""{"agent_instance":"1760860000000","sim_epoch":"3","sim_phase":"online"}""").jsonObject))
    }

    @Test
    fun agentInstanceIsReadAsAnExactLong() {
        assertEquals(SimIdentity(1760860000000L, 4, "changed"), SimIdentity.from(stamp(epoch = 4, phase = "changed")))
    }
}

package com.openu60.core.model

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * The agent's SIM identity stamp, inside `data` of /api/network/signal, /api/sim/info and
 * /api/esim/switch. `epoch` counts identity changes in one agent run; `phase` is idle, leaving,
 * changed, online or stalled.
 */
data class SimIdentity(val agentInstance: Long, val epoch: Long, val phase: String) {
    companion object {
        /** Null when the stamp is missing (older agents) or malformed. */
        fun from(data: JsonObject): SimIdentity? {
            val instance = number(data["agent_instance"]) ?: return null
            val epoch = number(data["sim_epoch"]) ?: return null
            val phase = (data["sim_phase"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            return SimIdentity(instance, epoch, phase)
        }

        private fun number(element: JsonElement?): Long? =
            (element as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
    }
}

/**
 * Tells open screens when the router's SIM identity moved: a profile switch, a SIM swap or an
 * agent restart. Reads the raw JsonObject, so the stamp is checked without converting the payload.
 */
class SimIdentityTracker {
    private var last: SimIdentity? = null

    /** True when the stamp differs from the last one; the first sighting only seeds. */
    @Synchronized
    fun observe(data: JsonObject): Boolean {
        val seen = SimIdentity.from(data) ?: return false
        val previous = last
        // A lower epoch from the same agent run is a late reply to an earlier request.
        if (previous != null && seen.agentInstance == previous.agentInstance && seen.epoch < previous.epoch) return false
        last = seen
        return previous != null && seen != previous
    }
}

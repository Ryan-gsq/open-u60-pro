package com.openu60.core.model

import com.openu60.core.network.toMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SMSForwardParserTest {
    /** Decodes the way AgentClient.getJSONArray does for each log entry. */
    private fun entry(json: String) =
        SMSForwardParser.parseLogEntry(Json.parseToJsonElement(json).jsonObject.toMap())

    @Test
    fun parsesAHeldEntry() {
        val held = entry("""{"timestamp":1700000000,"sms_id":12,"sender":"BANK","content_preview":"code",
            "rule_name":"All","destination_type":"telegram","success":false,
            "error":"no WAN connectivity; held for retry","pending":true}""")
        assertNotNull(held)
        assertTrue(held!!.pending)
        assertFalse(held.success)
        assertEquals("no WAN connectivity; held for retry", held.error)
    }

    @Test
    fun pendingDefaultsToFalseForOlderAgents() {
        val failed = entry("""{"timestamp":1700000000,"sms_id":13,"success":false,"error":"HTTP 500"}""")
        assertFalse(failed!!.pending)
        val sent = entry("""{"timestamp":1700000000,"sms_id":14,"success":true,"pending":false}""")
        assertTrue(sent!!.success)
        assertFalse(sent.pending)
    }
}

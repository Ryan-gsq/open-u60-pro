package com.openu60.core.network

import com.openu60.core.model.DeviceParser
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentJsonTest {
    private fun map(json: String) = Json.parseToJsonElement(json).jsonObject.toMap()

    @Test
    fun jsonStringsStayStrings() {
        val m = map("""{"sim_iccid":"89630000000000000027","sim_imsi":"515031234567890","msisdn":"+639170000000",
            "time":"03:00","ipv6":"2409:8a00::1","token":"123456:ABC-def","date":"24,05,01,12,00,00,+32",
            "command_id":"1792250909345","flag":"true","nan":"NaN","hex":"4E2D","empty":""}""")
        assertEquals("89630000000000000027", m["sim_iccid"])
        assertEquals("515031234567890", m["sim_imsi"])
        assertEquals("+639170000000", m["msisdn"])
        assertEquals("03:00", m["time"])
        assertEquals("2409:8a00::1", m["ipv6"])
        assertEquals("123456:ABC-def", m["token"])
        assertEquals("24,05,01,12,00,00,+32", m["date"])
        assertEquals("1792250909345", m["command_id"])
        assertEquals("true", m["flag"])
        assertEquals("NaN", m["nan"])
        assertEquals("4E2D", m["hex"])
        assertEquals("", m["empty"])
    }

    @Test
    fun jsonNumbersAndBooleansStillConvert() {
        val m = map("""{"i":-86,"l":1792250909345,"d":41.5,"b":true,"n":null,"nested":{"x":1},"arr":[1,"2"]}""")
        assertEquals(-86, m["i"])
        assertEquals(1792250909345L, m["l"])
        assertEquals(41.5, m["d"])
        assertEquals(true, m["b"])
        assertEquals(null, m["n"])
        assertEquals(1, (m["nested"] as Map<*, *>)["x"])
        assertEquals(listOf(1, "2"), m["arr"])
    }

    @Test
    fun tolerantHelpersStillReadNumericStrings() {
        assertEquals(41, DeviceParser.asInt("41.5"))
        assertEquals(-86, DeviceParser.asInt(" -86 "))
        assertEquals(1792250909345L, DeviceParser.asLong("1792250909345"))
        assertEquals(12.5, DeviceParser.asDouble("12.5"))
        assertEquals(null, DeviceParser.asInt("03:00"))
        assertTrue(DeviceParser.asBool("1") && DeviceParser.asBool("2") && DeviceParser.asBool("ON") && DeviceParser.asBool(1L))
        assertFalse(DeviceParser.asBool("0") || DeviceParser.asBool("off") || DeviceParser.asBool(""))
    }
}

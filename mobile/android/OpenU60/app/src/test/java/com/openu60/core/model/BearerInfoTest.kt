package com.openu60.core.model

import com.openu60.core.network.toMap
import com.openu60.feature.signal.SignalMonitorState
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BearerInfoTest {
    /** Decodes the way AgentClient does, so numbers arrive as Int or Double. */
    private fun signalData(json: String): Map<String, Any?> =
        Json.parseToJsonElement(json).jsonObject.toMap()

    @Test
    fun parsesTheAgentBearerObject() {
        val sa = SignalParser.parseBearer(signalData("""{"network_type":"NR5G-SA","bearer":{"qci":6,"ambr_dl_mbps":2000.0,"ambr_ul_mbps":200.0}}"""))
        assertEquals(BearerInfo(qci = 6, ambrDownlinkMbps = 2000.0, ambrUplinkMbps = 200.0), sa)
        assertEquals("2000 / 200 Mbps", sa?.ambrText)

        val lte = SignalParser.parseBearer(signalData("""{"bearer":{"qci":9,"ambr_dl_mbps":1200.0,"ambr_ul_mbps":8.64}}"""))
        assertEquals("1200 / 8.64 Mbps", lte?.ambrText)

        // Above parseSignalDouble's ±9000 sentinel cut-off.
        val fast = SignalParser.parseBearer(signalData("""{"bearer":{"qci":9,"ambr_dl_mbps":10000,"ambr_ul_mbps":2000}}"""))
        assertEquals(10000.0, fast?.ambrDownlinkMbps)
    }

    @Test
    fun keepsWhicheverValuesArePresent() {
        val qciOnly = SignalParser.parseBearer(signalData("""{"bearer":{"qci":8,"ambr_dl_mbps":null,"ambr_ul_mbps":null}}"""))
        assertEquals(BearerInfo(qci = 8), qciOnly)
        assertNull(qciOnly?.ambrText)

        val ambrOnly = SignalParser.parseBearer(signalData("""{"bearer":{"qci":null,"ambr_dl_mbps":0.5,"ambr_ul_mbps":null}}"""))
        assertNull(ambrOnly?.qci)
        assertEquals("0.5 / -- Mbps", ambrOnly?.ambrText)
    }

    @Test
    fun noSessionOldAgentOrNothingUsableIsNull() {
        assertNull(SignalParser.parseBearer(signalData("""{"bearer":null}""")))
        assertNull(SignalParser.parseBearer(signalData("""{"nr5g_rsrp":"-90"}""")))
        assertNull(SignalParser.parseBearer(signalData("""{"bearer":{"qci":0,"ambr_dl_mbps":0,"ambr_ul_mbps":-1}}""")))
    }

    @Test
    fun labelsTheQosIdentifierByNetworkMode() {
        listOf(
            "SA" to "5QI", "NR5G-SA" to "5QI", "5G_SA" to "5QI",
            "LTE-NSA" to "QCI", "ENDC" to "QCI", "LTE" to "QCI", "" to "QCI",
        ).forEach { (raw, label) -> assertEquals(raw, label, BearerInfo.qosLabel(raw)) }
        assertEquals("5QI", SignalMonitorState(operatorInfo = OperatorInfo(networkType = "NR5G-SA")).qosLabel)
    }

    @Test
    fun formatsMbps() {
        assertEquals("1200", BearerInfo.formatMbps(1200.0000000000002))
        assertEquals("0.03", BearerInfo.formatMbps(0.03))
    }
}

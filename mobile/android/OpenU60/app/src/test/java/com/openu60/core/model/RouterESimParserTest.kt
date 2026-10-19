package com.openu60.core.model

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RouterESimParserTest {
    /** Same configuration as AgentClient.get<T>(). */
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun keepsLongIdentifiersAsExactStrings() {
        val list = RouterESimParser.parseProfiles(json.decodeFromString<RouterESimProfilesResponse>("""
            {"enabled_iccid":"8963000000000000001","profiles":[
              {"class":"operational","iccid":"8963000000000000001","isdp_aid":"a0","name":"Operational","nickname":"Smart","provider":"SMART","state":"enabled"},
              {"class":"operational","iccid":"89630000000000000027","isdp_aid":"a1","name":"Globe Philippines ODC","nickname":null,"provider":"GOMO","state":"disabled"},
              {"class":"test","iccid":"8963000000000000003","isdp_aid":"a2","name":"","nickname":null,"provider":"Test","state":"disabled"},
              {"class":"operational","iccid":"","state":"disabled"}]}
        """))
        assertEquals(3, list.size)
        assertEquals("8963000000000000001", list[0].iccid)
        assertEquals("20-digit ICCIDs must not pass through a number", "89630000000000000027", list[1].iccid)
        assertTrue(list[0].isEnabled)
        assertEquals("Smart", list[0].displayName)
        assertFalse(list[0].canEnable)
        assertEquals("Globe Philippines ODC", list[1].displayName)
        assertTrue(list[1].canEnable)
        assertEquals("Test", list[2].displayName)
        assertFalse("test profiles cannot be enabled", list[2].canEnable)
    }

    @Test
    fun parsesChipWithoutLosingEidDigits() {
        val chip = RouterESimParser.parseChip(json.decodeFromString<RouterESimChipResponse>(
            """{"eid":"89000000000000000000000000000001","firmware":"4.2.0","free_nvm_bytes":972020,"free_ram_bytes":16574}""",
        ))
        assertEquals("89000000000000000000000000000001", chip.eid)
        assertEquals("4.2.0", chip.firmware)
        assertEquals(972020L, chip.freeMemoryBytes)
        assertEquals(RouterESimChip.empty, RouterESimParser.parseChip(RouterESimChipResponse()))
        val sim = json.decodeFromString<RouterESimSIMStatus>("""{"sim_iccid":"89630000000000000027","sim_states":"ready"}""")
        assertEquals("89630000000000000027", sim.iccid)
        assertEquals(null, json.decodeFromString<RouterESimSIMStatus>("""{"sim_iccid":null,"sim_states":null}""").iccid)
    }
    @Test
    fun reconnectionRequiresTheNewSimAndFreshConnectionEvidence() {
        assertFalse(RouterESimReconnectTracker.isConnected("disconnected"))
        assertFalse(RouterESimReconnectTracker.isConnected("connecting"))
        assertTrue(RouterESimReconnectTracker.isConnected("ipv4_ipv6_connected"))
        val tracker = RouterESimReconnectTracker("8963000000000000002")
        assertEquals(RouterESimConnectionPhase.RELOADING, tracker.phase("8963000000000000001", "connected", 3.0))
        assertEquals(RouterESimConnectionPhase.REGISTERING, tracker.phase("8963000000000000002", "connected", 6.0))
        assertEquals(RouterESimConnectionPhase.REGISTERING, tracker.phase("8963000000000000002", "disconnected", 9.0))
        assertEquals(RouterESimConnectionPhase.REGISTERING, tracker.phase("8963000000000000002", "connected", 26.0))
        assertEquals(RouterESimConnectionPhase.CONNECTED, tracker.phase("8963000000000000002", "connected", 29.0))
        val missedDrop = RouterESimReconnectTracker("8963000000000000002F")
        assertEquals(RouterESimConnectionPhase.REGISTERING, missedDrop.phase("8963000000000000002", "connected", 34.0))
        assertEquals(RouterESimConnectionPhase.REGISTERING, missedDrop.phase("8963000000000000002", "connected", 35.0))
        assertEquals(RouterESimConnectionPhase.CONNECTED, missedDrop.phase("8963000000000000002", "connected", 38.0))
        val waiting = RouterESimReconnectTracker("8963000000000000002")
        assertEquals(RouterESimConnectionPhase.WAITING, waiting.phase("8963000000000000001", "connected", 120.0))
        assertEquals(RouterESimConnectionPhase.WAITING, waiting.phase("8963000000000000001", "connected", 150.0))
    }


    @org.junit.Test
    fun activationCodesAndDownloadStages() {
        val activation = RouterESimActivationCode.parse("  \nlpa:1\$smdp.example.com:443\$ABC-123\n ")!!
        org.junit.Assert.assertEquals("LPA:1\$smdp.example.com:443\$ABC-123", activation.value)
        org.junit.Assert.assertFalse(activation.needsConfirmationCode)
        org.junit.Assert.assertTrue(RouterESimActivationCode.parse("LPA:1\$smdp.example.com\$ABC123\$1.3.6.1\$1")!!.needsConfirmationCode)
        org.junit.Assert.assertNotNull(RouterESimActivationCode.parse("LPA:1\$smdp.example.com\$\$\$"))
        listOf("https://example.com", "LPA:2\$server\$ABC", "LPA:1\$\$ABC", "LPA:1\$server", "LPA:1\$server\$AB C", "LPA:1\$server\$AB_C", "LPA:1\$server\$ABC\nDEF", "LPA:1\$server\$ABC\$0\$1\$extra", "LPA:1\$server\$" + "A".repeat(513)).forEach {
            org.junit.Assert.assertNull(RouterESimActivationCode.parse(it))
        }
        org.junit.Assert.assertTrue(RouterESimActivationCode.validConfirmationCode("123456"))
        listOf("", "1".repeat(65), "123\n").forEach { org.junit.Assert.assertFalse(RouterESimActivationCode.validConfirmationCode(it)) }
        val status = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }.decodeFromString<RouterESimDownloadStatus>("""{"state":"confirm","provider":"GOMO","iccid":"8963000000000000002","error":null,"started_at":123}""")
        org.junit.Assert.assertEquals("8963000000000000002", status.iccid)
        org.junit.Assert.assertTrue(status.isBusy && status.canCancel)
        org.junit.Assert.assertEquals("Ready to install", status.progressText)
        val install = status.copy(state = "running", step = "es10b_load_bound_profile_package")
        org.junit.Assert.assertTrue(install.isBusy)
        org.junit.Assert.assertFalse(install.canCancel)
        org.junit.Assert.assertEquals("Installing on the eSIM…", install.progressText)
        org.junit.Assert.assertFalse(status.copy(state = "cancelling").canCancel)
        org.junit.Assert.assertEquals("GOMO added.", status.copy(state = "done").progressText)
    }

    @Test
    fun inventoryCarriesFreshnessAndIgnoresOlderAnswers() {
        val inv = RouterESimParser.parseInventory(json.decodeFromString<RouterESimProfilesResponse>("""
            {"agent_instance":1792300000000,"generation":3,"observed_at":1792300100,"updating":false,"stale":true,
             "error":{"kind":"sim_reloading","message":"euicc_init","at":1792300110},"pending_receipts":1,
             "profiles":[{"class":"operational","iccid":"8963000000000000001","state":"enabled","provider":"SMART","name":"Operational","nickname":null}]}
        """))
        assertEquals(1792300000000L, inv.agentInstance)
        assertEquals(1, inv.pendingReceipts)
        assertEquals("The eSIM is still settling after the switch.", inv.errorText)
        assertTrue(inv.copy(generation = 2).isOlderThan(inv))
        assertTrue(inv.copy(observedAt = inv.observedAt - 1).isOlderThan(inv))
        assertFalse(inv.isOlderThan(inv.copy(generation = 2)))
        assertFalse("a restarted agent is never older", inv.copy(agentInstance = 1, generation = 0).isOlderThan(inv))
        val old = RouterESimParser.parseInventory(json.decodeFromString<RouterESimProfilesResponse>("""{"profiles":[],"error":null,"pending_receipts":null}"""))
        assertFalse("older agents carry no counters", old.isOlderThan(inv))
        assertEquals(null, old.errorText)
    }

    @Test
    fun switchStatusMapsToScreenPhases() {
        val sw = json.decodeFromString<RouterESimSwitchStatus>("""{"state":"card_confirmed","target_iccid":"89630000000000000027","generation":4,"started_at":1,"card_confirmed_at":7,"finished_at":0,"note":null}""")
        assertEquals("89630000000000000027", sw.targetICCID)
        assertTrue(sw.isRunning && sw.cardConfirmed)
        assertEquals(RouterESimConnectionPhase.REGISTERING, sw.phase)
        assertEquals(RouterESimConnectionPhase.RELOADING, RouterESimSwitchStatus("reloading").phase)
        assertFalse(RouterESimSwitchStatus("reloading").cardConfirmed)
        assertEquals(RouterESimConnectionPhase.CONNECTED, RouterESimSwitchStatus("connected").phase)
        assertEquals(RouterESimConnectionPhase.WAITING, RouterESimSwitchStatus("no_data").phase)
        assertTrue(RouterESimSwitchStatus("modem_unconfirmed").outcomeNote!!.contains("Restart the router"))
        val roaming = json.decodeFromString<RouterESimSwitchStatus>("""{"state":"no_data","reason":"roaming_off","note":null}""")
        assertTrue(roaming.outcomeNote!!.contains("Turn on Data Roaming"))
        assertTrue(RouterESimSwitchStatus("no_data", reason = "data_off").outcomeNote!!.contains("Mobile Data is off"))
        assertTrue(RouterESimSwitchStatus("no_data").outcomeNote!!.contains("plan or coverage"))
        assertEquals(RouterESimConnectionPhase.UNAVAILABLE, RouterESimSwitchStatus("not_applied").phase)
        assertFalse(RouterESimSwitchStatus("connected").isRunning)
    }
}

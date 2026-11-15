package nl.space.dddec.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class NcsdParserTest {

    /** Builds a minimal NCSD header with the given (offset, size) partitions in media units. */
    private fun ncsdHeader(mediaId: Long, vararg parts: Pair<Int, Int>, unitExp: Int = 0): ByteArray {
        val bb = ByteBuffer.allocate(0x200).order(ByteOrder.LITTLE_ENDIAN)
        bb.position(0x100); bb.put("NCSD".toByteArray())
        bb.putLong(0x108, mediaId)
        parts.forEachIndexed { i, (off, len) ->
            bb.putInt(0x120 + i * 8, off)
            bb.putInt(0x124 + i * 8, len)
        }
        bb.put(0x18E, unitExp.toByte())
        return bb.array()
    }

    @Test fun detectsNcsdMagic() {
        assertTrue(CiaParser.isNcsd(ncsdHeader(1L)))
        assertFalse(CiaParser.isNcsd(ByteArray(0x200)))
    }

    @Test fun parsesPartitionTableAndSkipsEmptySlots() {
        val hdr = ncsdHeader(1L, 0x20 to 0x1000, 0 to 0, 0x1020 to 0x80)
        val parts = CiaParser.parseNcsdPartitions(hdr)
        assertEquals(2, parts.size)
        assertEquals(CiaParser.NcsdPartition(0, 0x4000L, 0x200000L), parts[0])
        assertEquals(CiaParser.NcsdPartition(2, 0x1020L * 0x200, 0x80L * 0x200), parts[1])
    }

    @Test fun honoursMediaUnitExponent() {
        val parts = CiaParser.parseNcsdPartitions(ncsdHeader(1L, 0x10 to 0x10, unitExp = 1))
        assertEquals(0x10L * 0x400, parts[0].offset)
    }

    @Test fun readTitleInfoRecognisesCartridge() {
        val info = CiaParser.readTitleInfo(ncsdHeader(0x0004000000055D00L, 0x20 to 0x1000).inputStream())
        assertNotNull(info)
        assertTrue(info!!.isCartridge)
        assertEquals(0x0004000000055D00L, info.titleId)
    }
}

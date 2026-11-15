package nl.space.dddec.crypto

import java.io.DataInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object SeedDbParser {

    /**
     * Parses the seeddb.bin file and returns a map of Title ID → Seed.
     *
     * Format:
     *   Header (16 bytes):
     *     0x00 (Int LE): Number of entries
     *     0x04–0x0F:     Padding (zeros)
     *   Entry × N (32 bytes each):
     *     0x00 (Long LE): Title ID
     *     0x08 (16 bytes): Seed
     *     0x18 (Long LE): Title ID (repeated, for verification)
     *
     * IMPORTANT: uses DataInputStream.readFully() throughout.
     * Plain InputStream.read(buf) is NOT guaranteed to fill the buffer —
     * on Android SAF streams it routinely returns partial data, which silently
     * corrupts every seed entry and misaligns all subsequent reads.
     */
    fun parse(inputStream: InputStream): Map<Long, ByteArray> {
        val dis = DataInputStream(inputStream)

        val headerBuffer = ByteArray(16)
        dis.readFully(headerBuffer)
        val numEntries = ByteBuffer.wrap(headerBuffer).order(ByteOrder.LITTLE_ENDIAN).getInt(0)

        val seedMap = mutableMapOf<Long, ByteArray>()
        val entryBuffer = ByteArray(32)

        for (i in 0 until numEntries) {
            dis.readFully(entryBuffer)
            val bb = ByteBuffer.wrap(entryBuffer).order(ByteOrder.LITTLE_ENDIAN)

            val titleId = bb.getLong(0)
            val seed = ByteArray(16).also {
                bb.position(8)
                bb.get(it)
            }
            // Entry also has Title ID repeated at 0x18 — we ignore it (redundant)

            seedMap[titleId] = seed
        }

        return seedMap
    }
}
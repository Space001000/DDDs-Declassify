package nl.space.dddec.crypto

import nl.space.dddec.model.CiaHeader
import nl.space.dddec.model.NcchHeader
import nl.space.dddec.model.Ticket
import nl.space.dddec.model.Tmd
import nl.space.dddec.model.TmdContent
import java.nio.ByteBuffer
import java.nio.ByteOrder

object CiaParser {

    /** True if [header] (at least 0x104 bytes from file start) is an NCSD (.3ds / .cci) image. */
    fun isNcsd(header: ByteArray): Boolean =
        header.size >= 0x104 && String(header, 0x100, 4, Charsets.US_ASCII) == "NCSD"

    /** One NCCH partition inside an NCSD image, in bytes. */
    data class NcsdPartition(val index: Int, val offset: Long, val size: Long)

    /**
     * Reads the NCSD partition table: 8 entries of (offset, size) in media units at 0x120.
     * The media unit is 0x200 << flags[6] (flags at 0x188).
     */
    fun parseNcsdPartitions(header: ByteArray): List<NcsdPartition> {
        val bb = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val mediaUnit = 0x200L shl (header[0x18E].toInt() and 0x0F)
        return (0 until 8).mapNotNull { i ->
            val off = (bb.getInt(0x120 + i * 8).toLong() and 0xFFFFFFFFL) * mediaUnit
            val len = (bb.getInt(0x124 + i * 8).toLong() and 0xFFFFFFFFL) * mediaUnit
            if (len > 0) NcsdPartition(i, off, len) else null
        }
    }

    fun parseHeaderFromBuffer(bb: ByteBuffer): CiaHeader {
        bb.order(ByteOrder.LITTLE_ENDIAN)
        return CiaHeader(
            headerSize  = bb.getInt(0x00),
            type        = bb.getShort(0x04),
            version     = bb.getShort(0x06),
            certSize    = bb.getInt(0x08),
            ticketSize  = bb.getInt(0x0C),
            tmdSize     = bb.getInt(0x10),
            metaSize    = bb.getInt(0x14),
            contentSize = bb.getLong(0x18)
        )
    }

    /**
     * Returns the total size of the signature block that precedes the Ticket or TMD body.
     * The first 4 bytes (Big Endian) identify the type.
     *
     * Layout of a signature block:
     *   4 bytes  : signature type identifier  (already consumed when we detect the type)
     *   N bytes  : the actual signature bytes
     *   P bytes  : zero padding to align to 0x40
     *
     * The TOTAL block size (type + sig + padding) for each type:
     *   RSA-4096 : 4 + 0x200 + 0x3C = 0x240
     *   RSA-2048 : 4 + 0x100 + 0x3C = 0x140  ← most common in retail CIAs
     *   ECDSA    : 4 + 0x3C  + 0x40 = 0x80
     *
     * BUG HISTORY: a previous version returned 0x244/0x144/0x84 (4 bytes too large each).
     * That caused every body-relative offset to be shifted by +4 bytes, leading to
     * content_count reading as 0 and all content records being misaligned.
     */
    private fun getSignatureSize(bb: ByteBuffer): Int {
        bb.position(0)
        val sigType = bb.order(ByteOrder.BIG_ENDIAN).getInt()
        return when (sigType) {
            0x00010000 -> 0x240 // RSA-4096-SHA1
            0x00010001 -> 0x140 // RSA-2048-SHA1
            0x00010002 -> 0x80  // ECDSA-SHA1
            0x00010003 -> 0x240 // RSA-4096-SHA256
            0x00010004 -> 0x140 // RSA-2048-SHA256
            0x00010005 -> 0x80  // ECDSA-SHA256
            else       -> 0x140 // Default: retail RSA-2048
        }
    }

    /**
     * Parses the Ticket section.
     * All offsets are relative to the end of the signature block (body-relative).
     *
     *   body+0x7F  : Encrypted Title Key (16 bytes)
     *   body+0x9C  : Title ID (8 bytes, Big Endian)
     *   body+0xB1  : Common Key Index (1 byte)
     */
    fun parseTicketFromBuffer(bb: ByteBuffer, size: Int): Ticket {
        val sigSize = getSignatureSize(bb)
        bb.order(ByteOrder.BIG_ENDIAN)

        val encryptedTitleKey = ByteArray(16)
        bb.position(sigSize + 0x7F)
        bb.get(encryptedTitleKey)

        val titleId        = bb.getLong(sigSize + 0x9C)
        val commonKeyIndex = bb.get(sigSize + 0xB1).toInt() and 0xFF

        return Ticket(titleId, encryptedTitleKey, commonKeyIndex)
    }

    /**
     * Parses the TMD section.
     * All offsets are relative to the end of the signature block (body-relative).
     *
     *   body+0x4C  : Title ID (8 bytes, Big Endian)
     *   body+0x9E  : Content Count (2 bytes, Big Endian)
     *   body+0x9C4 : Content Chunk Records (contentCount × 0x30 bytes)
     *
     * Content records offset derivation:
     *   TMD body header      = 0xC4 bytes
     *   Content Info Records = 64 × 0x24 = 0x900 bytes
     *   Total                = 0xC4 + 0x900 = 0x9C4
     */
    fun parseTmdFromBuffer(bb: ByteBuffer, size: Int): Tmd {
        val sigSize = getSignatureSize(bb)
        bb.order(ByteOrder.BIG_ENDIAN)

        val titleId      = bb.getLong(sigSize + 0x4C)
        val titleVersion = bb.getShort(sigSize + 0x9C).toInt() and 0xFFFF
        val contentCount = bb.getShort(sigSize + 0x9E).toInt() and 0xFFFF

        val contentRecordsOffset = sigSize + 0x9C4

        if (contentRecordsOffset + (contentCount * 0x30) > size) {
            throw Exception(
                "TMD buffer too small: need ${contentRecordsOffset + (contentCount * 0x30)} " +
                        "bytes, have $size. contentCount=$contentCount sigSize=0x${sigSize.toString(16)}"
            )
        }

        bb.position(contentRecordsOffset)

        val contents = mutableListOf<TmdContent>()
        for (i in 0 until contentCount) {
            val contentId   = bb.getInt()
            val index       = bb.getShort().toInt() and 0xFFFF
            val type        = bb.getShort()
            val contentSize = bb.getLong()
            bb.position(bb.position() + 32) // skip SHA-256 hash
            contents.add(TmdContent(contentId, index, type, contentSize))
        }

        return Tmd(titleId, contentCount, contents, titleVersion)
    }

    /**
     * Reads Title ID and version from the start of a CIA stream (header + certs + ticket + TMD;
     * typically well under 64 KB). Returns null if the stream is not a parseable CIA.
     */
    fun readTitleInfo(input: java.io.InputStream): nl.space.dddec.model.TitleInfo? = try {
        val dis = java.io.DataInputStream(input)
        // 0x200 bytes covers both the CIA header (+bitmap start) and the NCSD header.
        val hdr = ByteArray(0x200).also { dis.readFully(it) }
        val header = parseHeaderFromBuffer(ByteBuffer.wrap(hdr))
        val tmdEnd = header.getTmdOffset() + header.tmdSize
        if (isNcsd(hdr)) {
            val mediaId = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN).getLong(0x108)
            nl.space.dddec.model.TitleInfo(mediaId, 0, isCartridge = true)
        } else if (header.tmdSize <= 0 || tmdEnd > 4L * 1024 * 1024 || tmdEnd < hdr.size) null
        else {
            val prefix = ByteArray(tmdEnd.toInt())
            System.arraycopy(hdr, 0, prefix, 0, hdr.size)
            dis.readFully(prefix, hdr.size, prefix.size - hdr.size)
            val tmdBytes = prefix.copyOfRange(header.getTmdOffset().toInt(), tmdEnd.toInt())
            val tmd = parseTmdFromBuffer(ByteBuffer.wrap(tmdBytes), header.tmdSize)
            nl.space.dddec.model.TitleInfo(tmd.titleId, tmd.titleVersion)
        }
    } catch (_: Exception) {
        null
    }

    /**
     * Parses the NCCH header from a buffer containing ALREADY DECRYPTED content bytes.
     * The buffer must start at byte 0 of the NCCH container.
     *
     *   0x000–0x0FF : RSA-2048 Signature (first 16 bytes used for seed key derivation)
     *   0x100–0x103 : Magic "NCCH"
     *   0x104–0x107 : Content Size in Media Units (× 512 = bytes)
     *   0x108–0x10F : Partition ID
     *   0x118–0x11F : Title ID / Program ID (Little Endian)
     *   0x188–0x18F : Flags (8 bytes)
     */
    fun parseNcchHeaderFromBuffer(bb: ByteBuffer): NcchHeader {
        bb.order(ByteOrder.LITTLE_ENDIAN)

        val headerSigBytes = ByteArray(16)
        bb.position(0x000)
        bb.get(headerSigBytes)

        val magic = ByteArray(4)
        bb.position(0x100)
        bb.get(magic)
        if (String(magic) != "NCCH") {
            throw Exception("Invalid NCCH magic: expected 'NCCH', got '${String(magic)}'")
        }

        val contentSize = bb.getInt(0x104).toLong() * 512  // media units → bytes

        // 0x110 = Partition ID, 0x118 = Program ID / Title ID
        val titleId = bb.getLong(0x118)

        val flags = ByteArray(8)
        bb.position(0x188)
        bb.get(flags)

        return NcchHeader(titleId, contentSize, flags, headerSigBytes)
    }
}
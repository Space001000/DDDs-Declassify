package nl.space.dddec.model

data class CiaHeader(
    val headerSize: Int,
    val type: Short,
    val version: Short,
    val certSize: Int,
    val ticketSize: Int,
    val tmdSize: Int,
    val metaSize: Int,
    val contentSize: Long
) {
    // The CIA header section is headerSize bytes long (always 0x2020 in practice):
    //   0x0000–0x001F : CIA header struct (32 bytes)
    //   0x0020–0x201F : Content bitmap (0x2000 bytes)
    // All subsequent sections are aligned to 64-byte boundaries.
    //
    // BUG HISTORY: getCertOffset() previously returned hardcoded 0x20L, which is only
    // the size of the header STRUCT, not the full header SECTION (0x2020 bytes).
    // This shifted every section offset 0x2000 bytes too early, causing the content
    // loop to read from the middle of the TMD instead of the start of the content.
    fun getCertOffset(): Long = align64(headerSize.toLong())
    fun getTicketOffset(): Long = align64(getCertOffset() + certSize)
    fun getTmdOffset(): Long = align64(getTicketOffset() + ticketSize)
    fun getContentOffset(): Long = align64(getTmdOffset() + tmdSize)
    fun getMetaOffset(): Long = align64(getContentOffset() + contentSize)

    private fun align64(offset: Long): Long = (offset + 0x3F) and 0x3FFFFFFFFFFFFFC0L
}

data class Ticket(
    val titleId: Long,
    val encryptedTitleKey: ByteArray,
    val commonKeyIndex: Int
)

data class TmdContent(
    val id: Int,
    val index: Int,
    val type: Short,
    val size: Long
)

data class Tmd(
    val titleId: Long,
    val contentCount: Int,
    val contents: List<TmdContent>,
    val titleVersion: Int = 0
)

/** Identity of a title, used to name output files so base games, updates and DLC never collide. */
data class TitleInfo(
    val titleId: Long,
    val version: Int,
    /** True for .3ds/.cci cartridge images (NCSD) rather than CIAs. */
    val isCartridge: Boolean = false
) {

    enum class Kind { GAME, UPDATE, DLC, DEMO, SYSTEM, OTHER }

    /** Upper 32 bits of the Title ID encode the title category. */
    val kind: Kind get() = when ((titleId ushr 32).toInt()) {
        0x00040000 -> Kind.GAME
        0x0004000E -> Kind.UPDATE
        0x0004008C -> Kind.DLC
        0x00040002 -> Kind.DEMO
        0x00040010, 0x0004001B, 0x00040030, 0x0004009B, 0x000400DB, 0x00040130, 0x00040138 -> Kind.SYSTEM
        else       -> Kind.OTHER
    }

    /** Title version as shown on the console: major.minor.micro (6/6/4 bits). */
    val versionString: String get() =
        "${version shr 10}.${(version shr 4) and 0x3F}.${version and 0xF}"

    val titleIdHex: String get() = "%016X".format(titleId)
}

data class NcchHeader(
    val titleId: Long,
    val contentSize: Long,
    val flags: ByteArray,
    // First 16 bytes of the NCCH RSA signature (0x000–0x00F).
    // Required for seed key derivation: SHA-256(headerSigBytes + seed)[0..15]
    val headerSigBytes: ByteArray
) {
    fun getCryptoMethod(): Int = flags[3].toInt() and 0xFF
    fun isFixedSystemKey(): Boolean = (flags[7].toInt() and 0x01) != 0
    // Bit 2 (0x04) = NoCrypto. Previously incorrectly used 0x02 (bit 1).
    fun isNoCrypto(): Boolean = (flags[7].toInt() and 0x04) != 0
    fun usesSeed(): Boolean = (flags[7].toInt() and 0x20) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as NcchHeader
        if (titleId != other.titleId) return false
        if (contentSize != other.contentSize) return false
        if (!flags.contentEquals(other.flags)) return false
        if (!headerSigBytes.contentEquals(other.headerSigBytes)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = titleId.hashCode()
        result = 31 * result + contentSize.hashCode()
        result = 31 * result + flags.contentHashCode()
        result = 31 * result + headerSigBytes.contentHashCode()
        return result
    }
}
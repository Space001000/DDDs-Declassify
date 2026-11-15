package nl.space.dddec.crypto

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import nl.space.dddec.model.Smdh
import nl.space.dddec.model.SmdhParser
import nl.space.dddec.model.Ticket
import java.io.RandomAccessFile
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {

    private const val AES_CBC = "AES/CBC/NoPadding"
    private const val AES_CTR = "AES/CTR/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val NCCH_HEADER_SIZE = 0x200
    private const val MEDIA_UNIT = 512L
    private const val BUFFER_SIZE = 1024 * 1024 // 1 MB, multiple of 16

    // NCCH KeyX slot name by crypto method flag value (flags[3])
    private val KEY_X_BY_CRYPTO_METHOD = mapOf(
        0x00 to "slot0x2CKeyX",
        0x01 to "slot0x25KeyX",
        0x0A to "slot0x18KeyX",
        0x0B to "slot0x1BKeyX"
    )

    // TMD content chunk record: type bit 0x0001 = content is CIA-encrypted (AES-CBC).
    private const val TMD_TYPE_ENCRYPTED = 0x0001

    private fun isCiaEncrypted(content: nl.space.dddec.model.TmdContent) =
        (content.type.toInt() and TMD_TYPE_ENCRYPTED) != 0

    // --- Public entry points ---

    /**
     * Extracts game identity (icon + title + publisher) from a CIA file without
     * performing the full decryption. Only the first content's data is processed.
     *
     * The CIA outer layer uses AES-CBC, which cannot be seeked into arbitrarily —
     * you must decrypt from the beginning of each content block. This function
     * does exactly that for Content 0 only, stopping as soon as the icon is found.
     * The temp file written here is at most a few MB.
     */
    suspend fun extractIconFromCia(
        context: Context,
        ciaUri: Uri,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore
    ): Smdh? = withContext(Dispatchers.IO) {
        val tempFile = java.io.File(context.cacheDir, "preview.tmp")
        try {
            context.contentResolver.openInputStream(ciaUri)?.use { stream ->
                // Read just enough of the file: CIA header section + ticket + TMD + first content.
                // We cap at 32 MB which comfortably covers the NCCH header and ExeFS for any game.
                val prefixSize = 32L * 1024 * 1024
                tempFile.outputStream().buffered(BUFFER_SIZE).use { out ->
                    val buf = ByteArray(BUFFER_SIZE)
                    var copied = 0L
                    while (copied < prefixSize) {
                        val n = stream.read(buf, 0, minOf(buf.size.toLong(), prefixSize - copied).toInt())
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        copied += n
                    }
                }
            } ?: return@withContext null

            RandomAccessFile(tempFile, "r").use { raf ->
                val headerBytes = ByteArray(0x20).also { raf.seek(0); raf.readFully(it) }
                val header = CiaParser.parseHeaderFromBuffer(ByteBuffer.wrap(headerBytes))

                val ticketBytes = ByteArray(header.ticketSize)
                    .also { raf.seek(header.getTicketOffset()); raf.readFully(it) }
                val ticket = CiaParser.parseTicketFromBuffer(ByteBuffer.wrap(ticketBytes), header.ticketSize)

                val tmdBytes = ByteArray(header.tmdSize)
                    .also { raf.seek(header.getTmdOffset()); raf.readFully(it) }
                val tmd = CiaParser.parseTmdFromBuffer(ByteBuffer.wrap(tmdBytes), header.tmdSize)

                val content0 = tmd.contents.firstOrNull { it.index == 0 }
                    ?: tmd.contents.firstOrNull()
                    ?: return@use null

                // CIA layer (AES-CBC) only applies if the TMD marks the content encrypted.
                val ciaEncrypted = isCiaEncrypted(content0)
                val titleKey = if (ciaEncrypted) decryptTitleKey(ticket, keyStore) else null
                val ciaIv = ciaContentIv(content0.index)
                fun newCbc(): Cipher? = titleKey?.let { cbcDecryptCipher(it, ciaIv) }
                fun Cipher?.dec(b: ByteArray, len: Int = b.size): ByteArray? =
                    if (this == null) b.copyOf(len) else update(b, 0, len)

                // Decrypt Content 0's NCCH header
                val cbcCipher = newCbc()
                val encHdr = ByteArray(NCCH_HEADER_SIZE)
                    .also { raf.seek(header.getContentOffset()); raf.readFully(it) }
                val decHdr = cbcCipher.dec(encHdr)
                    ?: return@use null

                val bbNcch = ByteBuffer.wrap(decHdr).order(ByteOrder.LITTLE_ENDIAN)
                val magic = ByteArray(4).also { bbNcch.position(0x100); bbNcch.get(it) }
                if (String(magic) != "NCCH") return@use null

                val flags7       = bbNcch.get(0x18F).toInt() and 0xFF
                val partitionId  = bbNcch.getLong(0x108)
                val exefsOff     = (bbNcch.getInt(0x1A0).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT
                if (exefsOff == 0L) return@use null

                val originalKeyY = BigInteger(1, decHdr.copyOf(16))
                val normalKey2C  = if (flags7 and 0x01 != 0) ByteArray(16)
                else deriveNormalKey("slot0x2CKeyX", originalKeyY, keyStore)

                // Decrypt ExeFS header with CBC (CIA layer), then CTR (NCCH layer)
                val exefsAbs    = header.getContentOffset() + exefsOff
                val encExeHdr   = ByteArray(NCCH_HEADER_SIZE)
                val encExeIv    = ByteArray(16) // The 16 bytes immediately before exefsAbs in CBC stream

                // For CBC we must decrypt the entire stream from content start to exefsAbs.
                // Reinit the cipher and walk through in chunks, keeping the last 16 bytes as IV.
                // CBC is self-synchronising: the IV for any block is the previous ciphertext
                // block, so we can seek directly instead of walking the whole stream.
                fun cbcAt(relOff: Long): Cipher? {
                    if (titleKey == null) return null
                    if (relOff == 0L) return cbcDecryptCipher(titleKey, ciaIv)
                    val prev = ByteArray(16)
                    raf.seek(header.getContentOffset() + relOff - 16); raf.readFully(prev)
                    return cbcDecryptCipher(titleKey, prev)
                }

                raf.seek(header.getContentOffset() + exefsOff)
                raf.readFully(encExeHdr)
                val decExeHdrCia = cbcAt(exefsOff).dec(encExeHdr) ?: return@use null

                // NCCH CTR layer on top
                val ivExeFS     = makeIv(partitionId, 0x02)
                val ctrCipher   = ctrDecryptCipher(normalKey2C, bigIntTo16Bytes(ivExeFS))
                val decExeHdr   = ctrCipher.update(decExeHdrCia) ?: return@use null

                // Find the "icon" entry in the ExeFS header (10 entries × 16 bytes)
                for (i in 0 until 10) {
                    val name = String(decExeHdr, i * 16, 8, Charsets.US_ASCII).trimEnd('\u0000')
                    val off  = ByteBuffer.wrap(decExeHdr, i * 16 + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    val sz   = ByteBuffer.wrap(decExeHdr, i * 16 + 12, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

                    if (name != "icon" || sz < 0x36C0) continue

                    // Decrypt the icon data: CBC walk from just after ExeFS header to icon offset, then CTR
                    val iconRelOff  = 0x200 + off // relative to ExeFS start
                    // Read a 16-byte-aligned span so CBC/CTR stay block-aligned
                    val alignedSz = (sz + 0xF) and 0xF.inv().toLong()
                    val encIcon = ByteArray(alignedSz.toInt())
                    raf.seek(header.getContentOffset() + exefsOff + iconRelOff)
                    raf.readFully(encIcon)
                    val decIconCia = cbcAt(exefsOff + iconRelOff).dec(encIcon) ?: return@use null

                    val decIcon = if (flags7 and 0x04 == 0) {
                        val iconIv = bigIntTo16Bytes(ivPlusBlocks(ivExeFS, iconRelOff / 16))
                        ctrDecryptCipher(normalKey2C, iconIv).doFinal(decIconCia)
                    } else {
                        decIconCia
                    }

                    return@use SmdhParser.parse(decIcon)
                }
                null
            }
        } catch (e: Exception) {
            android.util.Log.w("DDDsDecryptor", "Preview failed", e)
            null
        } finally {
            tempFile.delete()
        }
    }

    suspend fun decryptCia(
        context: Context,
        ciaUri: Uri,
        destUri: Uri,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore,
        convertToCci: Boolean = false,
        onStatusUpdate: (String) -> Unit,
        onProgressUpdate: (Float) -> Unit,
        onSmdhLoaded: (Smdh) -> Unit = {}
    ) = withContext(Dispatchers.IO) {
        val tempInput  = java.io.File(context.cacheDir, "cia_input.tmp")
        val tempOutput = java.io.File(context.cacheDir, "cia_output.tmp")
        try {
            // Disk space check: we need ~2x the input size in cache
            context.contentResolver.openFileDescriptor(ciaUri, "r")?.use { pfd ->
                val inputSize = pfd.statSize
                if (inputSize > 0) {
                    val needed = inputSize * 2
                    val stats  = android.os.StatFs(context.cacheDir.absolutePath)
                    val free   = stats.availableBlocksLong * stats.blockSizeLong
                    if (free < needed) {
                        throw Exception(
                            "Not enough space in internal storage. " +
                                    "Need ${needed / 1024 / 1024} MB, have ${free / 1024 / 1024} MB."
                        )
                    }
                }
            }

            onStatusUpdate("Copying input to cache...")
            context.contentResolver.openInputStream(ciaUri)?.use { src ->
                tempInput.outputStream().buffered(BUFFER_SIZE).use { src.copyTo(it, BUFFER_SIZE) }
            } ?: throw Exception("Cannot open input file")

            onStatusUpdate("Stripping CIA encryption layer...")
            RandomAccessFile(tempInput, "r").use { rafIn ->
                RandomAccessFile(tempOutput, "rw").use { rafOut ->
                    rafOut.setLength(0)
                    decryptCiaLayer(rafIn, rafOut, seeds, keyStore, onStatusUpdate, onProgressUpdate)
                }
            }

            onStatusUpdate("Decrypting NCCH inner layer...")
            RandomAccessFile(tempOutput, "rw").use { raf ->
                decryptNcchLayer(raf, seeds, keyStore, onStatusUpdate, onProgressUpdate, onSmdhLoaded)
            }

            onStatusUpdate(if (convertToCci) "Assembling CCI file..." else "Finalizing output file...")
            context.contentResolver.openFileDescriptor(destUri, "w")?.use { pfd ->
                java.io.FileOutputStream(pfd.fileDescriptor).use { fos ->
                    RandomAccessFile(tempOutput, "r").use { rafIn ->
                        if (convertToCci) {
                            assembleCci(rafIn, fos, onProgressUpdate)
                        } else {
                            val channel   = rafIn.channel
                            val totalSize = channel.size()
                            var position  = 0L
                            while (position < totalSize) {
                                val transferred = channel.transferTo(
                                    position,
                                    minOf(BUFFER_SIZE.toLong(), totalSize - position),
                                    fos.channel
                                )
                                if (transferred <= 0) break
                                position += transferred
                                onProgressUpdate(0.9f + position.toFloat() / totalSize * 0.1f)
                            }
                        }
                    }
                }
            } ?: throw Exception("Cannot open output file")

            onProgressUpdate(1.0f)
            onStatusUpdate("Done! Fully decrypted file saved.")

        } finally {
            // Errors propagate to the caller, which reports them and removes partial output.
            tempInput.delete()
            tempOutput.delete()
        }
    }

    // --- .3ds / .cci (NCSD cartridge image) ---

    /**
     * Decrypts a .3ds/.cci cartridge image. There is no CIA layer, ticket or TMD: each
     * partition is a plain NCCH container, decrypted in place with the same NCCH logic.
     * Needs ~1x the input size in cache (vs 2x for CIA).
     */
    suspend fun decryptCartridge(
        context: Context,
        inUri: Uri,
        destUri: Uri,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore,
        onStatusUpdate: (String) -> Unit,
        onProgressUpdate: (Float) -> Unit,
        onSmdhLoaded: (Smdh) -> Unit = {}
    ) = withContext(Dispatchers.IO) {
        val work = java.io.File(context.cacheDir, "cci_work.tmp")
        try {
            context.contentResolver.openFileDescriptor(inUri, "r")?.use { pfd ->
                val inputSize = pfd.statSize
                val stats = android.os.StatFs(context.cacheDir.absolutePath)
                val free  = stats.availableBlocksLong * stats.blockSizeLong
                if (inputSize > 0 && free < inputSize) {
                    throw Exception(
                        "Not enough space in internal storage. " +
                                "Need ${inputSize / 1024 / 1024} MB, have ${free / 1024 / 1024} MB."
                    )
                }
            }

            onStatusUpdate("Copying input to cache...")
            context.contentResolver.openInputStream(inUri)?.use { src ->
                work.outputStream().buffered(BUFFER_SIZE).use { src.copyTo(it, BUFFER_SIZE) }
            } ?: throw Exception("Cannot open input file")
            onProgressUpdate(0.2f)

            RandomAccessFile(work, "rw").use { raf ->
                val hdr = ByteArray(0x200).also { raf.seek(0); raf.readFully(it) }
                if (!CiaParser.isNcsd(hdr)) throw Exception("Not a .3ds/.cci cartridge image (no NCSD header).")
                val partitions = CiaParser.parseNcsdPartitions(hdr)
                if (partitions.isEmpty()) throw Exception("Cartridge image has no partitions.")

                val fileSize  = raf.length()
                val totalSize = partitions.sumOf { it.size }
                var done      = 0L
                for (p in partitions) {
                    onProgressUpdate(0.2f + done.toFloat() / totalSize * 0.7f)
                    if (p.offset + 0x200 > fileSize) {
                        onStatusUpdate("Partition ${p.index}: outside file (trimmed dump?), skipping.")
                        continue
                    }
                    val ncchHdr = ByteArray(0x200).also { raf.seek(p.offset); raf.readFully(it) }
                    val bb = ByteBuffer.wrap(ncchHdr).order(ByteOrder.LITTLE_ENDIAN)
                    val ncch = try {
                        CiaParser.parseNcchHeaderFromBuffer(bb)
                    } catch (e: Exception) {
                        onStatusUpdate("Partition ${p.index}: not a valid NCCH, leaving as-is.")
                        done += p.size
                        continue
                    }
                    onStatusUpdate("Partition ${p.index}: decrypting...")
                    decryptNcchInPlace(
                        raf, p.offset, ncch, bb, p.index, seeds, keyStore, onStatusUpdate, onSmdhLoaded
                    )
                    done += p.size
                }
                raf.channel.force(true)
            }

            onStatusUpdate("Writing output file...")
            context.contentResolver.openFileDescriptor(destUri, "w")?.use { pfd ->
                java.io.FileOutputStream(pfd.fileDescriptor).use { fos ->
                    RandomAccessFile(work, "r").use { rafIn ->
                        val channel = rafIn.channel
                        val total   = channel.size()
                        var pos     = 0L
                        while (pos < total) {
                            val n = channel.transferTo(pos, minOf(BUFFER_SIZE.toLong(), total - pos), fos.channel)
                            if (n <= 0) break
                            pos += n
                            onProgressUpdate(0.9f + pos.toFloat() / total * 0.1f)
                        }
                    }
                }
            } ?: throw Exception("Cannot open output file")

            onProgressUpdate(1.0f)
            onStatusUpdate("Done! Fully decrypted file saved.")
        } finally {
            work.delete()
        }
    }

    /** Reads icon + title from partition 0 of a .3ds/.cci image (plain NCCH, no CIA layer). */
    suspend fun extractIconFromCartridge(
        context: Context,
        uri: Uri,
        keyStore: KeyStore
    ): Smdh? = withContext(Dispatchers.IO) {
        val tempFile = java.io.File(context.cacheDir, "preview_cci.tmp")
        try {
            // Partition 0's header and ExeFS sit near the start of the image.
            val prefixSize = 32L * 1024 * 1024
            context.contentResolver.openInputStream(uri)?.use { s ->
                tempFile.outputStream().buffered(BUFFER_SIZE).use { out ->
                    val buf = ByteArray(BUFFER_SIZE)
                    var copied = 0L
                    while (copied < prefixSize) {
                        val n = s.read(buf, 0, minOf(buf.size.toLong(), prefixSize - copied).toInt())
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        copied += n
                    }
                }
            } ?: return@withContext null

            RandomAccessFile(tempFile, "r").use { raf ->
                val hdr = ByteArray(0x200).also { raf.readFully(it) }
                if (!CiaParser.isNcsd(hdr)) return@use null
                val p0 = CiaParser.parseNcsdPartitions(hdr).firstOrNull { it.index == 0 } ?: return@use null
                readIconFromNcch(raf, p0.offset, keyStore)
            }
        } catch (e: Exception) {
            android.util.Log.w("DDDsDecryptor", "Cartridge preview failed", e)
            null
        } finally {
            tempFile.delete()
        }
    }

    /** Reads the SMDH icon from an NCCH at [ncchPos] whose bytes are not CIA-encrypted. */
    private fun readIconFromNcch(raf: RandomAccessFile, ncchPos: Long, keyStore: KeyStore): Smdh? {
        val hdr = ByteArray(0x200).also { raf.seek(ncchPos); raf.readFully(it) }
        val bb  = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
        val ncch = CiaParser.parseNcchHeaderFromBuffer(bb)
        val flags7      = ncch.flags[7].toInt() and 0xFF
        val noCrypto    = flags7 and 0x04 != 0
        val partitionId = bb.getLong(0x108)
        val exefsOff    = (bb.getInt(0x1A0).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT
        if (exefsOff == 0L) return null

        val key2C = when {
            noCrypto             -> null
            flags7 and 0x01 != 0 -> ByteArray(16)
            else                 -> deriveNormalKey("slot0x2CKeyX", BigInteger(1, ncch.headerSigBytes), keyStore)
        }
        val ivExeFS = makeIv(partitionId, 0x02)

        val exeHdr = ByteArray(0x200).also { raf.seek(ncchPos + exefsOff); raf.readFully(it) }
        val decExeHdr = key2C?.let { ctrDecryptCipher(it, bigIntTo16Bytes(ivExeFS)).doFinal(exeHdr) } ?: exeHdr

        for (i in 0 until 10) {
            val name = String(decExeHdr, i * 16, 8, Charsets.US_ASCII).trimEnd('\u0000')
            if (name != "icon") continue
            val off = ByteBuffer.wrap(decExeHdr, i * 16 + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            val sz  = ByteBuffer.wrap(decExeHdr, i * 16 + 12, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            if (sz < 0x36C0) return null
            val relOff = 0x200 + off
            val data = ByteArray(sz.toInt()).also { raf.seek(ncchPos + exefsOff + relOff); raf.readFully(it) }
            val dec = key2C?.let {
                ctrDecryptCipher(it, bigIntTo16Bytes(ivPlusBlocks(ivExeFS, relOff / 16))).doFinal(data)
            } ?: data
            return SmdhParser.parse(dec)
        }
        return null
    }

    // --- Stage 2: strip CIA AES-CBC layer ---

    private fun decryptCiaLayer(
        rafIn: RandomAccessFile,
        rafOut: RandomAccessFile,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore,
        onStatusUpdate: (String) -> Unit,
        onProgressUpdate: (Float) -> Unit
    ) {
        val headerBytes = ByteArray(0x20).also { rafIn.seek(0); rafIn.readFully(it) }
        val header = CiaParser.parseHeaderFromBuffer(ByteBuffer.wrap(headerBytes))

        val ticketBytes = ByteArray(header.ticketSize)
            .also { rafIn.seek(header.getTicketOffset()); rafIn.readFully(it) }
        val ticket = CiaParser.parseTicketFromBuffer(ByteBuffer.wrap(ticketBytes), header.ticketSize)

        val tmdBytes = ByteArray(header.tmdSize)
            .also { rafIn.seek(header.getTmdOffset()); rafIn.readFully(it) }
        val tmd = CiaParser.parseTmdFromBuffer(ByteBuffer.wrap(tmdBytes), header.tmdSize)

        onStatusUpdate("Found ${tmd.contentCount} content(s).")
        // Only needed if at least one content is CIA-encrypted.
        val titleKey by lazy { decryptTitleKey(ticket, keyStore) }

        // Copy metadata verbatim (header + certs + ticket + TMD)
        val contentStart = header.getContentOffset()
        rafIn.channel.transferTo(0, contentStart, rafOut.channel)
        var writtenBytes = contentStart

        val totalSize = tmd.contents.fold(0L) { acc, c -> acc + c.size }
        var totalDone = 0L
        var inPos = contentStart
        rafOut.seek(writtenBytes)

        tmd.contents.forEachIndexed { idx, content ->
            if (content.size == 0L) return@forEachIndexed

            val encrypted = isCiaEncrypted(content)
            onStatusUpdate(
                "CIA layer — content $idx: ${content.size / 1024 / 1024} MB" +
                        if (encrypted) "..." else " (not CIA-encrypted, copying)..."
            )

            // Only contents flagged encrypted in the TMD carry the AES-CBC layer.
            val cipher = if (encrypted) cbcDecryptCipher(titleKey, ciaContentIv(content.index)) else null

            var done = 0L
            val buf  = ByteArray(BUFFER_SIZE)
            rafIn.seek(inPos)

            while (done < content.size) {
                val toRead = minOf(BUFFER_SIZE.toLong(), content.size - done).toInt()
                val read   = rafIn.read(buf, 0, toRead)
                if (read <= 0) throw Exception("Unexpected end of file in content $idx")

                if (cipher == null) {
                    rafOut.write(buf, 0, read)
                } else {
                    val dec = if (done + read >= content.size) cipher.doFinal(buf, 0, read)
                    else cipher.update(buf, 0, read)
                    if (dec != null && dec.isNotEmpty()) rafOut.write(dec)
                }

                inPos        += read
                writtenBytes += read
                done         += read
                totalDone    += read
                onProgressUpdate(totalDone.toFloat() / totalSize * 0.5f)
            }

            val pad = (align64(writtenBytes) - writtenBytes).toInt()
            if (pad > 0) { rafOut.write(ByteArray(pad)); writtenBytes += pad }
            inPos = align64(inPos)
        }

        if (header.metaSize > 0) {
            copyRange(rafIn, rafOut, header.getMetaOffset(), header.metaSize.toLong())
        }
        rafOut.channel.force(true)
    }

    // --- Stage 3: decrypt NCCH inner layer in-place ---

    private fun decryptNcchLayer(
        raf: RandomAccessFile,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore,
        onStatusUpdate: (String) -> Unit,
        onProgressUpdate: (Float) -> Unit,
        onSmdhLoaded: (Smdh) -> Unit
    ) {
        val headerBytes = ByteArray(0x20).also { raf.seek(0); raf.readFully(it) }
        val header = CiaParser.parseHeaderFromBuffer(ByteBuffer.wrap(headerBytes))

        val tmdBytes = ByteArray(header.tmdSize)
            .also { raf.seek(header.getTmdOffset()); raf.readFully(it) }
        val tmd = CiaParser.parseTmdFromBuffer(ByteBuffer.wrap(tmdBytes), header.tmdSize)

        var contentPos = header.getContentOffset()
        val totalSize  = tmd.contents.fold(0L) { acc, c -> acc + c.size }
        var totalDone  = 0L

        tmd.contents.forEachIndexed { idx, content ->
            if (content.size == 0L) return@forEachIndexed

            onStatusUpdate("NCCH layer — content $idx...")
            onProgressUpdate(0.5f + totalDone.toFloat() / totalSize * 0.4f)

            val ncchHdrBytes = ByteArray(0x200).also { raf.seek(contentPos); raf.readFully(it) }
            val bb   = ByteBuffer.wrap(ncchHdrBytes).order(ByteOrder.LITTLE_ENDIAN)
            val ncch = try {
                CiaParser.parseNcchHeaderFromBuffer(bb)
            } catch (e: Exception) {
                // CIA layer was already stripped; content bytes are unchanged otherwise,
                // so the TMD hash stays valid — only the encrypted flag must be cleared.
                onStatusUpdate("Content $idx: not a valid NCCH (${e.message}), leaving as-is.")
                markContentDecrypted(raf, header, idx, contentPos, content, rehash = false)
                contentPos = align64(contentPos + content.size)
                totalDone += content.size
                return@forEachIndexed
            }

            val result = decryptNcchInPlace(
                raf, contentPos, ncch, bb, idx, seeds, keyStore, onStatusUpdate, onSmdhLoaded
            )
            if (result == NcchResult.ALREADY_PLAIN) {
                markContentDecrypted(raf, header, idx, contentPos, content, rehash = false)
            } else {
                onStatusUpdate("Content $idx: Updating TMD hash...")
                markContentDecrypted(raf, header, idx, contentPos, content, rehash = true)
            }

            totalDone += content.size
            contentPos = align64(contentPos + content.size)
        }

        updateTmdInfoRecordHashes(raf, header)
        raf.channel.force(true)
    }

    private enum class NcchResult { DECRYPTED, ALREADY_PLAIN }

    /**
     * Decrypts one NCCH container in place (ExHeader, ExeFS, RomFS) and stamps it NoCrypto.
     * Shared by the CIA path (one NCCH per content) and the .3ds path (one per partition).
     * [idx] 0 is the main game; its icon is reported through [onSmdhLoaded].
     */
    private fun decryptNcchInPlace(
        raf: RandomAccessFile,
        contentPos: Long,
        ncch: nl.space.dddec.model.NcchHeader,
        bb: ByteBuffer,
        idx: Int,
        seeds: Map<Long, ByteArray>,
        keyStore: KeyStore,
        onStatusUpdate: (String) -> Unit,
        onSmdhLoaded: (Smdh) -> Unit
    ): NcchResult {
            val flags7 = ncch.flags[7].toInt() and 0xFF

            if (flags7 and 0x04 != 0) {
                onStatusUpdate("Content $idx: NCCH already plaintext.")
                return NcchResult.ALREADY_PLAIN
            }

            // KeyY — seed-derived if required, otherwise from NCCH header signature
            var keyYBytes = ncch.headerSigBytes
            if (flags7 and 0x20 != 0) {
                val seed = seeds[ncch.titleId]
                    ?: throw Exception(
                        "Seed not found for title 0x${"%016X".format(ncch.titleId)}. " +
                                "Load a seeddb.bin that contains it."
                    )
                onStatusUpdate("Content $idx: seed found, deriving key...")
                keyYBytes = deriveSeedKey(ncch.headerSigBytes, seed)
            }

            val originalKeyY = BigInteger(1, ncch.headerSigBytes)
            val derivedKeyY  = BigInteger(1, keyYBytes)
            val partitionId  = bb.order(ByteOrder.LITTLE_ENDIAN).getLong(0x108)

            val exhdrSize = bb.getInt(0x180).toLong() and 0xFFFFFFFFL
            val exefsOff  = (bb.getInt(0x1A0).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT
            val exefsSize = (bb.getInt(0x1A4).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT
            val romfsOff  = (bb.getInt(0x1B0).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT
            val romfsSize = (bb.getInt(0x1B4).toLong() and 0xFFFFFFFFL) * MEDIA_UNIT

            // Key 2C always used for ExHeader + ExeFS header. Uses original (pre-seed) KeyY.
            val normalKey2C = if (flags7 and 0x01 != 0) ByteArray(16)
            else deriveNormalKey("slot0x2CKeyX", originalKeyY, keyStore)

            // RomFS and .code use the crypto-method key. Uses seed-derived KeyY if applicable.
            val cryptoMethod = ncch.flags[3].toInt() and 0xFF
            val normalKey    = if (flags7 and 0x01 != 0) ByteArray(16)
            else {
                val keyXName = KEY_X_BY_CRYPTO_METHOD[cryptoMethod] ?: "slot0x2CKeyX"
                deriveNormalKey(keyXName, derivedKeyY, keyStore)
            }

            // ExHeader + ACI (0x200 from NCCH base, total exhdrSize + 0x400 bytes)
            if (exhdrSize > 0) {
                val exhdrAbs   = contentPos + 0x200L
                val totalBytes = exhdrSize + 0x400L
                decryptCtrInPlace(raf, exhdrAbs, totalBytes, normalKey2C, makeIv(partitionId, 0x01))

                // Sanity check: JumpID at ExHeader+0x1C8 should equal Program ID
                val exhdrBuf = ByteArray(0x200).also { raf.seek(exhdrAbs); raf.readFully(it) }
                val jumpId   = ByteBuffer.wrap(exhdrBuf, 0x1C8, 8).order(ByteOrder.LITTLE_ENDIAN).long
                if (jumpId == ncch.titleId) {
                    onStatusUpdate("Content $idx: ExHeader decrypted OK (JumpID verified).")
                } else {
                    onStatusUpdate(
                        "Content $idx: WARNING — JumpID 0x${"${"%016X".format(jumpId)}"} " +
                                "!= ProgramID 0x${"${"%016X".format(ncch.titleId)}"}. " +
                                "Key or IV may be wrong."
                    )
                }
            }

            // ExeFS
            if (exefsSize > 0) {
                val exefsAbs = contentPos + exefsOff
                val ivExeFS  = makeIv(partitionId, 0x02)

                // ExeFS header (always key 2C)
                decryptCtrInPlace(raf, exefsAbs, 0x200, normalKey2C, ivExeFS)

                // Read decrypted ExeFS header to find icon and .code ranges
                val hdrBuf = ByteArray(0x200).also { raf.seek(exefsAbs); raf.readFully(it) }
                var codeStart = -1L
                var codeEnd   = -1L

                for (i in 0 until 10) {
                    val entryName = String(hdrBuf, i * 16, 8, Charsets.US_ASCII).trimEnd('\u0000')
                    val off = ByteBuffer.wrap(hdrBuf, i * 16 + 8,  4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    val sz  = ByteBuffer.wrap(hdrBuf, i * 16 + 12, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

                    if (entryName == ".code") {
                        codeStart = 0x200 + off
                        codeEnd   = codeStart + ((sz + 0x1FF) and 0x1FF.inv())
                    }

                    if (idx == 0 && entryName == "icon" && sz > 0) {
                        val iconRelOff = 0x200 + off
                        val iconAbs    = exefsAbs + iconRelOff
                        val iconData   = ByteArray(sz.toInt()).also { raf.seek(iconAbs); raf.readFully(it) }
                        val decIcon    = if (flags7 and 0x04 == 0) {
                            val ivIcon = bigIntTo16Bytes(ivPlusBlocks(ivExeFS, iconRelOff / 16))
                            ctrDecryptCipher(normalKey2C, ivIcon).doFinal(iconData)
                        } else {
                            iconData
                        }
                        try { onSmdhLoaded(SmdhParser.parse(decIcon)) } catch (_: Exception) {}
                    }
                }

                // ExeFS body — split at .code boundary if dual-key
                if (codeStart != -1L) {
                    val preSize = codeStart - 0x200
                    if (preSize > 0) {
                        decryptCtrInPlace(raf, exefsAbs + 0x200, preSize, normalKey2C,
                            ivPlusBlocks(ivExeFS, 0x200 / 16))
                    }
                    decryptCtrInPlace(raf, exefsAbs + codeStart, codeEnd - codeStart, normalKey,
                        ivPlusBlocks(ivExeFS, codeStart / 16))
                    val postSize = exefsSize - codeEnd
                    if (postSize > 0) {
                        decryptCtrInPlace(raf, exefsAbs + codeEnd, postSize, normalKey2C,
                            ivPlusBlocks(ivExeFS, codeEnd / 16))
                    }
                } else {
                    val bodySize = exefsSize - 0x200
                    if (bodySize > 0) {
                        decryptCtrInPlace(raf, exefsAbs + 0x200, bodySize, normalKey2C,
                            ivPlusBlocks(ivExeFS, 0x200 / 16))
                    }
                }
                onStatusUpdate("Content $idx: ExeFS decrypted.")
            }

            // RomFS
            if (romfsSize > 0) {
                decryptCtrInPlace(raf, contentPos + romfsOff, romfsSize, normalKey,
                    makeIv(partitionId, 0x03))
                onStatusUpdate("Content $idx: RomFS decrypted.")
            }

            // NCCH header hashes (0x160 / 0x1C0 / 0x1E0) are computed over plaintext
            // hash regions, so they remain valid after decryption — leave them untouched.

            // Stamp NoCrypto flag: clear CryptoMethod (flags[3]) and Seed+FixedKey bits,
            // set NoCrypto bit so emulators skip re-decryption
            raf.seek(contentPos + 0x18B); raf.write(0x00)
            raf.seek(contentPos + 0x18F); raf.write((flags7 and 0x21.inv()) or 0x04)

            return NcchResult.DECRYPTED
    }

    // --- TMD fix-ups ---

    private fun tmdSigSize(raf: RandomAccessFile, header: nl.space.dddec.model.CiaHeader): Int {
        val buf = ByteArray(4).also { raf.seek(header.getTmdOffset()); raf.readFully(it) }
        val sigType = buf.fold(0) { acc, b -> (acc shl 8) or (b.toInt() and 0xFF) }
        return when (sigType) {
            0x00010000, 0x00010003 -> 0x240
            0x00010002, 0x00010005 -> 0x80
            else                   -> 0x140
        }
    }

    /**
     * Clears the "encrypted" bit of TMD content record [idx] (the CIA layer is gone for
     * every content we output) and, if the content bytes changed, stores its new SHA-256.
     */
    private fun markContentDecrypted(
        raf: RandomAccessFile,
        header: nl.space.dddec.model.CiaHeader,
        idx: Int,
        contentPos: Long,
        content: nl.space.dddec.model.TmdContent,
        rehash: Boolean
    ) {
        val recordBase = header.getTmdOffset() + tmdSigSize(raf, header) + 0x9C4 + (idx * 0x30)

        val typeBuf = ByteArray(2).also { raf.seek(recordBase + 0x06); raf.readFully(it) }
        val newType = (((typeBuf[0].toInt() and 0xFF) shl 8) or (typeBuf[1].toInt() and 0xFF)) and
                TMD_TYPE_ENCRYPTED.inv()
        raf.seek(recordBase + 0x06)
        raf.write((newType shr 8) and 0xFF)
        raf.write(newType and 0xFF)

        if (rehash) {
            val contentHash = hashRange(raf, contentPos, content.size)
            raf.seek(recordBase + 0x10)
            raf.write(contentHash)
        }
    }

    /**
     * After editing content chunk records, recompute the hashes that cover them:
     *   - each Content Info Record (body+0xC4, 64 × 0x24) hashes a range of chunk records
     *   - the TMD header (body+0xA4) hashes all 64 Content Info Records
     */
    private fun updateTmdInfoRecordHashes(raf: RandomAccessFile, header: nl.space.dddec.model.CiaHeader) {
        val body        = header.getTmdOffset() + tmdSigSize(raf, header)
        val infoBase    = body + 0xC4
        val chunkBase   = body + 0x9C4

        for (i in 0 until 64) {
            val rec = ByteArray(4).also { raf.seek(infoBase + i * 0x24); raf.readFully(it) }
            val indexOffset = ((rec[0].toInt() and 0xFF) shl 8) or (rec[1].toInt() and 0xFF)
            val commandCount = ((rec[2].toInt() and 0xFF) shl 8) or (rec[3].toInt() and 0xFF)
            if (commandCount == 0) continue
            val hash = hashRange(raf, chunkBase + indexOffset * 0x30L, commandCount * 0x30L)
            raf.seek(infoBase + i * 0x24 + 4)
            raf.write(hash)
        }

        val infoHash = hashRange(raf, infoBase, 64 * 0x24L)
        raf.seek(body + 0xA4)
        raf.write(infoHash)
    }

    // --- AES-CTR in-place decryption ---

    private fun decryptCtrInPlace(
        raf: RandomAccessFile,
        fileOffset: Long,
        size: Long,
        key: ByteArray,
        ivInt: BigInteger
    ) {
        val keySpec    = SecretKeySpec(key, KEY_ALGORITHM)
        val buf        = ByteArray(BUFFER_SIZE)
        var remaining  = size
        var pos        = fileOffset
        var blockCount = 0L

        while (remaining > 0) {
            val toRead = minOf(BUFFER_SIZE.toLong(), remaining).toInt()
            raf.seek(pos)
            val read = raf.read(buf, 0, toRead)
            if (read <= 0) break

            val batchIv = bigIntTo16Bytes(ivPlusBlocks(ivInt, blockCount))
            val cipher  = Cipher.getInstance(AES_CTR)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(batchIv))
            val dec = cipher.doFinal(buf, 0, read)

            raf.seek(pos)
            raf.write(dec, 0, read)

            blockCount += read / 16
            pos        += read
            remaining  -= read
        }
    }

    // --- IV construction ---

    /**
     * Builds a 128-bit AES-CTR IV from a Partition ID and a region type byte.
     * The Partition ID is stored LE in the NCCH header but used BE in the IV.
     *   bytes 0-7 : Partition ID, byte-reversed (LE→BE)
     *   byte  8   : region type (0x01=ExHeader, 0x02=ExeFS, 0x03=RomFS)
     *   bytes 9-15: zero
     */
    private fun makeIv(partitionIdLE: Long, typeByte: Int): BigInteger {
        val ivBytes = ByteArray(16)
        for (i in 0..7) ivBytes[i] = (partitionIdLE shr ((7 - i) * 8)).toByte()
        ivBytes[8] = typeByte.toByte()
        return BigInteger(1, ivBytes)
    }

    private fun ciaContentIv(contentIndex: Int): ByteArray {
        val iv = ByteArray(16)
        iv[0] = (contentIndex shr 8).toByte()
        iv[1] = (contentIndex and 0xFF).toByte()
        return iv
    }

    private fun ivPlusBlocks(iv: BigInteger, blocks: Long): BigInteger {
        val mask = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
        return iv.add(BigInteger.valueOf(blocks)).and(mask)
    }

    private fun bigIntTo16Bytes(n: BigInteger): ByteArray {
        val raw = n.toByteArray()
        return when {
            raw.size > 16 -> raw.copyOfRange(raw.size - 16, raw.size)
            raw.size < 16 -> ByteArray(16 - raw.size) + raw
            else          -> raw
        }
    }

    // --- Cipher helpers ---

    private fun cbcDecryptCipher(key: ByteArray, iv: ByteArray): Cipher =
        Cipher.getInstance(AES_CBC).also {
            it.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
        }

    private fun ctrDecryptCipher(key: ByteArray, iv: ByteArray): Cipher =
        Cipher.getInstance(AES_CTR).also {
            it.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
        }

    // --- Key derivation ---

    private fun decryptTitleKey(ticket: Ticket, keyStore: KeyStore): ByteArray {
        val idx = ticket.commonKeyIndex
        val commonKey = keyStore.commonKey(idx)
            ?: throw Exception(
                "Common key index $idx not found in aes_keys.txt " +
                        "(need slot0x3DKeyX + common$idx, or common_key_$idx)."
            )
        val iv = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            .putLong(ticket.titleId).put(ByteArray(8)).array()
        return cbcDecryptCipher(commonKey, iv).doFinal(ticket.encryptedTitleKey)
    }

    private fun deriveNormalKey(keyXName: String, keyY: BigInteger, keyStore: KeyStore): ByteArray {
        val keyXBytes = Keys.getKey(keyXName, keyStore)
            ?: throw Exception("Missing key: $keyXName")
        return scrambleKey(keyXBytes, bigIntTo16Bytes(keyY), keyStore)
    }

    fun deriveSeedKey(ncchHeaderSigBytes: ByteArray, seed: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(ncchHeaderSigBytes)
        md.update(seed)
        return md.digest().copyOf(16)
    }

    /** 3DS hardware key scrambler: NormalKey = ROL128((ROL128(KeyX, 2) XOR KeyY) + C, 87). */
    fun scrambleKey(keyX: ByteArray, keyY: ByteArray, keyStore: KeyStore): ByteArray {
        val generator = Keys.getKey("generator", keyStore)
            ?: throw Exception("Missing key: generator (scrambler constant) in aes_keys.txt")
        return scrambleKey(keyX, keyY, generator)
    }

    fun scrambleKey(keyX: ByteArray, keyY: ByteArray, generator: ByteArray): ByteArray {
        val x    = BigInteger(1, keyX)
        val y    = BigInteger(1, keyY)
        val g    = BigInteger(1, generator)
        val mask = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
        fun rol128(v: BigInteger, n: Int) =
            v.shiftLeft(n).or(v.shiftRight(128 - n)).and(mask)
        val r = rol128(rol128(x, 2).xor(y).add(g).and(mask), 87)
        return bigIntTo16Bytes(r)
    }

    // --- File I/O helpers ---

    private fun copyRange(src: RandomAccessFile, dst: RandomAccessFile, start: Long, length: Long) {
        src.seek(start)
        val buf = ByteArray(BUFFER_SIZE)
        var rem = length
        while (rem > 0) {
            val r = src.read(buf, 0, minOf(BUFFER_SIZE.toLong(), rem).toInt())
            if (r <= 0) break
            dst.write(buf, 0, r)
            rem -= r
        }
    }

    private fun hashRange(raf: RandomAccessFile, start: Long, length: Long): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        raf.seek(start)
        val buf = ByteArray(BUFFER_SIZE)
        var rem = length
        while (rem > 0) {
            val r = raf.read(buf, 0, minOf(BUFFER_SIZE.toLong(), rem).toInt())
            if (r <= 0) break
            md.update(buf, 0, r)
            rem -= r
        }
        return md.digest()
    }

    // --- CCI assembly ---

    private fun assembleCci(
        rafIn: RandomAccessFile,
        fos: java.io.FileOutputStream,
        onProgressUpdate: (Float) -> Unit
    ) {
        val outChannel  = fos.channel
        val headerBytes = ByteArray(0x20).also { rafIn.seek(0); rafIn.readFully(it) }
        val header      = CiaParser.parseHeaderFromBuffer(ByteBuffer.wrap(headerBytes))

        val tmdBytes = ByteArray(header.tmdSize)
            .also { rafIn.seek(header.getTmdOffset()); rafIn.readFully(it) }
        val tmd = CiaParser.parseTmdFromBuffer(ByteBuffer.wrap(tmdBytes), header.tmdSize)

        val ncsdHeader       = ByteBuffer.allocate(0x200).order(ByteOrder.LITTLE_ENDIAN)
        val ncsdHeaderSize   = 0x4000L
        var currentOffsetUnits = ncsdHeaderSize / MEDIA_UNIT

        ncsdHeader.position(0x100)
        ncsdHeader.put("NCSD".toByteArray())
        ncsdHeader.putLong(0x108, tmd.titleId)

        outChannel.write(ByteBuffer.allocate(ncsdHeaderSize.toInt()))

        val totalSize   = tmd.contents.fold(0L) { acc, c -> acc + c.size }
        var totalWritten = 0L
        var ciaPos      = header.getContentOffset()

        tmd.contents.forEachIndexed { idx, content ->
            if (idx >= 8 || content.size == 0L) return@forEachIndexed

            val entryOffset = 0x120 + (idx * 8)
            ncsdHeader.putInt(entryOffset,     currentOffsetUnits.toInt())
            ncsdHeader.putInt(entryOffset + 4, (alignMediaUnit(content.size) / MEDIA_UNIT).toInt())

            val inChannel = rafIn.channel
            var written   = 0L
            while (written < content.size) {
                val toRead     = minOf(BUFFER_SIZE.toLong(), content.size - written)
                val transferred = inChannel.transferTo(ciaPos + written, toRead, outChannel)
                if (transferred <= 0) break
                written      += transferred
                totalWritten += transferred
                onProgressUpdate(0.9f + totalWritten.toFloat() / totalSize * 0.1f)
            }

            val pad = (alignMediaUnit(content.size) - content.size).toInt()
            if (pad > 0) outChannel.write(ByteBuffer.allocate(pad))

            currentOffsetUnits += alignMediaUnit(content.size) / MEDIA_UNIT
            ciaPos = align64(ciaPos + content.size)
        }

        ncsdHeader.putInt(0x104, currentOffsetUnits.toInt())
        ncsdHeader.rewind()
        outChannel.position(0)
        outChannel.write(ncsdHeader)
    }

    // --- Alignment ---

    private fun alignMediaUnit(n: Long) = (n + 0x1FF) and 0x1FF.inv().toLong()
    private fun align64(n: Long)        = (n + 0x3F) and 0x3F.inv().toLong()

    fun hexToBytes(hex: String) =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
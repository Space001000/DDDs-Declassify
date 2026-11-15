package nl.space.dddec.model

import android.graphics.Bitmap
import android.graphics.Color

data class Smdh(
    val shortDescription: String,
    val longDescription: String,
    val publisher: String,
    val icon: Bitmap?
)

object SmdhParser {
    fun parse(bytes: ByteArray): Smdh {
        // SMDH is 0x36C0 bytes
        // Titles start at 0x08. There are 16 languages, each 0x200 bytes.
        // We'll use English (index 1) if available, otherwise index 0.
        // Each title struct: 0x80 Short Desc, 0x100 Long Desc, 0x80 Publisher (UTF-16)
        
        // English first; region-locked titles (e.g. Japan-only) may only fill other languages.
        val langOrder = listOf(1) + (0 until 16).filter { it != 1 }
        val lang = langOrder.firstOrNull { readUtf16(bytes, 0x08 + it * 0x200, 0x80).isNotBlank() } ?: 1
        val titleOffset = 0x08 + lang * 0x200
        val shortDesc = readUtf16(bytes, titleOffset, 0x80)
        val longDesc = readUtf16(bytes, titleOffset + 0x80, 0x100)
        val publisher = readUtf16(bytes, titleOffset + 0x180, 0x80)
        
        // Icon is at 0x24C0. 48x48 pixels, RGB565, tiled (8x8)
        val icon = try {
            parseIcon(bytes, 0x24C0)
        } catch (e: Exception) {
            null
        }

        return Smdh(shortDesc, longDesc, publisher, icon)
    }

    private fun readUtf16(data: ByteArray, offset: Int, maxLen: Int): String {
        val sb = StringBuilder()
        for (i in 0 until maxLen step 2) {
            val charCode = (data[offset + i].toInt() and 0xFF) or ((data[offset + i + 1].toInt() and 0xFF) shl 8)
            if (charCode == 0) break
            sb.append(charCode.toChar())
        }
        return sb.toString().trim()
    }

    private fun parseIcon(data: ByteArray, offset: Int): Bitmap {
        val bitmap = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
        // RGB565, 48x48 tiled 8x8 with 3DS hardware swizzle
        var dataIdx = offset
        for (ty in 0 until 48 step 8) {
            for (tx in 0 until 48 step 8) {
                for (i in 0 until 64) {
                    // Correct 3DS Morton swizzle:
                    // i = y2 x2 y1 x1 y0 x0
                    val x = (i and 1) or ((i and 4) shr 1) or ((i and 16) shr 2)
                    val y = ((i and 2) shr 1) or ((i and 8) shr 2) or ((i and 32) shr 3)

                    val low = data[dataIdx++].toInt() and 0xFF
                    val high = data[dataIdx++].toInt() and 0xFF
                    val rgb565 = (high shl 8) or low
                    
                    val r = ((rgb565 shr 11) and 0x1F) shl 3
                    val g = ((rgb565 shr 5) and 0x3F) shl 2
                    val b = (rgb565 and 0x1F) shl 3
                    
                    bitmap.setPixel(tx + x, ty + y, Color.rgb(r, g, b))
                }
            }
        }
        return bitmap
    }
}

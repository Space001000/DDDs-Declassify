package nl.space.dddec.crypto

import java.io.File

/** Finds an existing aes_keys.txt in the places it usually lives. */
object KeyFileFinder {

    /** Where aes_keys.txt usually lives, relative to a storage volume root. */
    private val KNOWN_RELATIVE_PATHS = listOf(
        "Download/aes_keys.txt",
        "Downloads/aes_keys.txt",
        "aes_keys.txt",
        "Azahar/sysdata/aes_keys.txt",
        "azahar-emu/sysdata/aes_keys.txt",
        "citra-emu/sysdata/aes_keys.txt",
        "Citra/sysdata/aes_keys.txt",
        "lime3ds/sysdata/aes_keys.txt",
        "Lime3DS/sysdata/aes_keys.txt",
        "gm9/out/aes_keys.txt",
        "gm9/support/aes_keys.txt",
        "3ds/aes_keys.txt"
    )

    /**
     * Checks well-known locations on internal storage and any SD cards.
     * Requires broad storage access (All files access on Android 11+); returns null otherwise.
     */
    fun findOnDisk(): File? {
        val roots = buildList {
            add(android.os.Environment.getExternalStorageDirectory())
            File("/storage").listFiles()
                ?.filter { it.isDirectory && it.name != "emulated" && it.name != "self" }
                ?.let { addAll(it) }
        }
        for (root in roots) {
            for (rel in KNOWN_RELATIVE_PATHS) {
                val f = File(root, rel)
                if (f.isFile && f.canRead()) return f
            }
        }
        return null
    }
}

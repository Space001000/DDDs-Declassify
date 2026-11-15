package nl.space.dddec.crypto

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract

/**
 * Finds an existing aes_keys.txt inside a folder the user granted access to (SAF tree URI).
 *
 * Android does not let apps scan shared storage freely, so the user picks a folder once
 * (e.g. internal storage root, an SD card, or an emulator's user folder) and this searches it.
 * Typical locations:
 *   <azahar or citra user folder>/sysdata/aes_keys.txt
 *   <sd root>/gm9/out/aes_keys.txt, gm9/support/aes_keys.txt
 */
object KeyFileFinder {

    private const val TARGET = "aes_keys.txt"
    private const val MAX_DEPTH = 5
    private const val MAX_DIRS = 1500

    // Folders likely to contain the keys are searched first.
    private val PREFERRED = listOf(
        "sysdata", "azahar", "citra", "lime3ds", "gm9", "out", "support", "3ds"
    )

    // Large or irrelevant folders that are never worth descending into.
    private val SKIP = setOf(
        "android", "dcim", "pictures", "movies", "music", "notifications", "ringtones",
        "alarms", "podcasts", "audiobooks", "recordings", "screenshots", "thumbnails",
        "cache", "shaders", "screenshots", "load", "dump", "nand", "sdmc", "title"
    )

    private data class Entry(val docId: String, val name: String, val isDir: Boolean)

    /** Returns the document URI of the first aes_keys.txt found, or null. Blocking: call off the main thread. */
    fun find(context: Context, treeUri: Uri): Uri? {
        val rootId = DocumentsContract.getTreeDocumentId(treeUri)
        val queue = ArrayDeque<Pair<String, Int>>().apply { add(rootId to 0) }
        var visited = 0

        while (queue.isNotEmpty() && visited < MAX_DIRS) {
            val (dirId, depth) = queue.removeFirst()
            visited++
            val children = list(context, treeUri, dirId)

            children.firstOrNull { !it.isDir && it.name.equals(TARGET, ignoreCase = true) }
                ?.let { return DocumentsContract.buildDocumentUriUsingTree(treeUri, it.docId) }

            if (depth >= MAX_DEPTH) continue
            val dirs = children.filter { it.isDir && !it.name.startsWith(".") && it.name.lowercase() !in SKIP }
            val (preferred, rest) = dirs.partition { d -> PREFERRED.any { d.name.lowercase().contains(it) } }
            // Preferred folders jump the queue so typical locations are found quickly.
            preferred.asReversed().forEach { queue.addFirst(it.docId to depth + 1) }
            rest.forEach { queue.addLast(it.docId to depth + 1) }
        }
        return null
    }

    private fun list(context: Context, treeUri: Uri, parentId: String): List<Entry> {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        return try {
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { c ->
                buildList {
                    while (c.moveToNext()) {
                        val id   = c.getString(0) ?: continue
                        val name = c.getString(1) ?: continue
                        val dir  = c.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR
                        add(Entry(id, name, dir))
                    }
                }
            } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }
}

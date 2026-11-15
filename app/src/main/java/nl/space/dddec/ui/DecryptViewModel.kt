package nl.space.dddec.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.space.dddec.crypto.CiaParser
import nl.space.dddec.crypto.CryptoUtils
import nl.space.dddec.model.TitleInfo
import nl.space.dddec.crypto.FileNameUtils
import nl.space.dddec.crypto.KeyStore
import nl.space.dddec.crypto.SeedDbParser

class DecryptViewModel(application: Application) : AndroidViewModel(application) {

    var ciaFileUri    by mutableStateOf<Uri?>(null)
    var seedDbUri     by mutableStateOf<Uri?>(null)
    var keysFileUri   by mutableStateOf<Uri?>(null)
    var destinationUri by mutableStateOf<Uri?>(null)

    var seedDbMap  by mutableStateOf<Map<Long, ByteArray>?>(null)
    var keyStore   by mutableStateOf(KeyStore.empty())

    var exportToCci       by mutableStateOf(false)
    var suggestedFileName by mutableStateOf("decrypted_game.cia")
    var statusMessage     by mutableStateOf("Load seeddb.bin to begin.")
    var isProcessing      by mutableStateOf(false)
    var progress          by mutableStateOf(0f)
    var currentSmdh       by mutableStateOf<nl.space.dddec.model.Smdh?>(null)

    var batchQueue         by mutableStateOf<List<Uri>>(emptyList())
    var currentBatchIndex  by mutableStateOf(0)

    /** Seeds shipped in assets/seeddb.bin; a user-loaded seeddb is merged on top. */
    private var bundledSeeds: Map<Long, ByteArray> = emptyMap()

    init {
        bundledSeeds = try {
            application.assets.open("seeddb.bin").use { SeedDbParser.parse(it) }
        } catch (e: Exception) {
            android.util.Log.w("DDDsDecryptor", "Bundled seeddb.bin unavailable", e)
            emptyMap()
        }
        seedDbMap = bundledSeeds.takeIf { it.isNotEmpty() }
        loadPersistedUris()
    }

    // --- Setup ---

    fun toggleExportFormat(isCci: Boolean) {
        exportToCci = isCci
        updateSuggestedName()
    }

    private fun updateSuggestedName() {
        val uri = ciaFileUri ?: return
        viewModelScope.launch {
            val info = titleInfo(uri)
            suggestedFileName = outputName(getFileName(uri) ?: "game.cia", info, romTitle(uri, info))
            // romTitle() loaded the SMDH; reuse it for the icon/title preview.
            if (ciaFileUri == uri) smdhCache[uri]?.let { currentSmdh = it }
        }
    }

    // --- Embedded game title (SMDH) ---

    private val smdhCache = mutableMapOf<Uri, nl.space.dddec.model.Smdh?>()

    /** Game titles seen this session, keyed by the low 32 bits of the Title ID, which a base
     *  game shares with its update and DLC. Lets updates/DLC (no icon of their own) borrow it. */
    private val titleByUniqueId = mutableMapOf<Long, String>()

    private fun uniqueId(info: TitleInfo) = info.titleId and 0xFFFFFFFFL

    private suspend fun smdh(uri: Uri): nl.space.dddec.model.Smdh? {
        if (smdhCache.containsKey(uri)) return smdhCache[uri]
        val result = CryptoUtils.extractIconFromCia(
            context  = getApplication(),
            ciaUri   = uri,
            seeds    = seedDbMap ?: emptyMap(),
            keyStore = keyStore
        )
        // Don't cache a miss while keys are absent; it may succeed once keys load.
        if (result != null || keyStore.isUsable) smdhCache[uri] = result
        return result
    }

    /** Title embedded in the CIA, or the related base game's title; null falls back to the filename. */
    private suspend fun romTitle(uri: Uri, info: TitleInfo?): String? {
        val own = smdh(uri)?.shortDescription?.takeIf { it.isNotBlank() }
        if (info != null) {
            if (own != null && info.kind == TitleInfo.Kind.GAME) titleByUniqueId[uniqueId(info)] = own
            if (own == null || info.kind != TitleInfo.Kind.GAME) {
                titleByUniqueId[uniqueId(info)]?.let { return it }
            }
        }
        return own
    }

    // --- Title identity (for naming and CCI eligibility) ---

    private val titleInfoCache = mutableMapOf<Uri, TitleInfo?>()

    private suspend fun titleInfo(uri: Uri): TitleInfo? {
        if (titleInfoCache.containsKey(uri)) return titleInfoCache[uri]
        val info = withContext(Dispatchers.IO) {
            try {
                getApplication<Application>().contentResolver.openInputStream(uri)
                    ?.use { CiaParser.readTitleInfo(it) }
            } catch (_: Exception) {
                null
            }
        }
        titleInfoCache[uri] = info
        return info
    }

    /** CCI is a cartridge image: only meaningful for base games, never updates or DLC. */
    private fun wantsCci(info: TitleInfo?) =
        exportToCci && (info == null || info.kind == TitleInfo.Kind.GAME)

    private fun outputName(originalName: String, info: TitleInfo?, romTitle: String?): String {
        val baseName = FileNameUtils.cleanAndSuggest(originalName, info, romTitle)
            .removeSuffix(".cia").removeSuffix(".cci")
        return if (wantsCci(info)) "$baseName.cci" else "$baseName.cia"
    }

    private fun loadPersistedUris() {
        val prefs = getApplication<Application>().getSharedPreferences("prefs", Context.MODE_PRIVATE)
        val seedUri = prefs.getString("seeddb_uri", null)
        val keysUri = prefs.getString("keys_uri", null)
        if (seedUri != null) {
            try { onSeedDbSelected(Uri.parse(seedUri), persist = false) } catch (_: Exception) {}
        }
        if (keysUri != null) {
            try { onKeysFileSelected(Uri.parse(keysUri), persist = false) } catch (_: Exception) {}
        }
        updateStatus()
    }

    fun onKeysFileSelected(uri: Uri?, persist: Boolean = true) {
        keysFileUri = uri
        if (uri == null) return
        try {
            if (persist) {
                getApplication<Application>().contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
                prefs().edit().putString("keys_uri", uri.toString()).apply()
            }
            val text = getApplication<Application>().contentResolver.openInputStream(uri)
                ?.bufferedReader()?.readText()
                ?: throw Exception("Cannot read file")
            keyStore = KeyStore.parse(text)
            updateStatus()
        } catch (e: Exception) {
            statusMessage = "Error loading keys file: ${e.localizedMessage}"
            if (!persist) prefs().edit().remove("keys_uri").apply()
        }
    }

    /** Searches a user-picked folder (Azahar/Citra user folder, SD root, ...) for aes_keys.txt. */
    fun onKeysFolderSelected(treeUri: Uri?) {
        if (treeUri == null) return
        statusMessage = "Searching for aes_keys.txt..."
        viewModelScope.launch {
            val found = withContext(Dispatchers.IO) {
                try {
                    nl.space.dddec.crypto.KeyFileFinder.find(getApplication(), treeUri)
                } catch (e: Exception) {
                    android.util.Log.w("DDDsDecryptor", "Key search failed", e)
                    null
                }
            }
            if (found == null) {
                statusMessage = "No aes_keys.txt found in that folder.\n" +
                        "Try your Azahar/Citra user folder or the SD card root, or pick the file directly."
                return@launch
            }
            // Keep access to the folder so the found file can be reopened on next launch.
            try {
                getApplication<Application>().contentResolver.takePersistableUriPermission(
                    treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
                prefs().edit().putString("keys_uri", found.toString()).apply()
            } catch (_: Exception) {
                // Not persistable: keys still work for this session.
            }
            onKeysFileSelected(found, persist = false)
        }
    }

    fun onSeedDbSelected(uri: Uri?, persist: Boolean = true) {
        seedDbUri = uri
        if (uri == null) return
        try {
            if (persist) {
                getApplication<Application>().contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
                prefs().edit().putString("seeddb_uri", uri.toString()).apply()
            }
            getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                // User-supplied entries win over bundled ones (e.g. a newer seeddb).
                seedDbMap = bundledSeeds + SeedDbParser.parse(input)
            }
            updateStatus()
        } catch (e: Exception) {
            statusMessage = "Error loading SeedDB: ${e.localizedMessage}"
            if (!persist) prefs().edit().remove("seeddb_uri").apply()
        }
    }

    private fun updateStatus() {
        val keysOk  = keyStore.isUsable
        val seedsOk = seedDbMap != null
        statusMessage = when {
            keysFileUri != null && !keysOk ->
                "aes_keys.txt is missing: ${keyStore.missingEssentials().joinToString()}."
            !keysOk ->
                "Load aes_keys.txt (dumped from your own 3DS) to begin."
            !seedsOk ->
                "Keys loaded (${keyStore.keyCount}). Ready.\n" +
                        "Optional: load seeddb.bin for seeded titles."
            else ->
                "Ready. Keys: ${keyStore.keyCount}  Seeds: ${seedDbMap?.size}" +
                        if (seedDbUri == null) " (built-in)" else ""
        }
    }

    // --- File selection ---

    fun onCiaFileSelected(uri: Uri?) {
        ciaFileUri = uri
        currentSmdh = null
        if (uri != null) {
            updateSuggestedName()
            batchQueue = emptyList()
            statusMessage = "CIA selected: ${getFileName(uri)}"
        }
    }

    fun onCiaFilesSelected(uris: List<Uri>) {
        if (uris.isEmpty()) return
        if (uris.size == 1) {
            onCiaFileSelected(uris[0])
        } else {
            batchQueue   = uris
            ciaFileUri   = uris[0]
            currentBatchIndex = 0
            updateSuggestedName()
            statusMessage = "Batch selected: ${uris.size} files. Ready to process."
        }
    }

    fun onDestinationSelected(uri: Uri?) {
        destinationUri = uri
        if (uri != null && ciaFileUri != null) {
            startDecryption()
        }
    }

    // --- Decryption ---

    private fun startDecryption() {
        val input  = ciaFileUri     ?: return
        val output = destinationUri ?: return

        isProcessing = true
        progress     = 0f

        viewModelScope.launch {
            val cci = wantsCci(titleInfo(input))
            val error = runDecrypt(input, output, cci) { status -> statusMessage = status }
            if (error != null) statusMessage = "Error: $error"
            isProcessing = false
        }
    }

    /** Runs one decryption. Returns null on success or an error message (partial output removed). */
    private suspend fun runDecrypt(
        input: Uri, output: Uri, cci: Boolean, onStatus: (String) -> Unit
    ): String? =
        try {
            CryptoUtils.decryptCia(
                context          = getApplication(),
                ciaUri           = input,
                destUri          = output,
                seeds            = seedDbMap ?: emptyMap(),
                keyStore         = keyStore,
                convertToCci     = cci,
                onStatusUpdate   = onStatus,
                onProgressUpdate = { p -> progress = p },
                onSmdhLoaded     = { smdh -> currentSmdh = smdh }
            )
            null
        } catch (e: kotlinx.coroutines.CancellationException) {
            deleteOutput(output)
            throw e
        } catch (e: Exception) {
            android.util.Log.e("DDDsDecryptor", "Decryption failed", e)
            deleteOutput(output)
            e.localizedMessage ?: e.javaClass.simpleName
        }

    private suspend fun deleteOutput(uri: Uri) = withContext(Dispatchers.IO) {
        try {
            DocumentsContract.deleteDocument(getApplication<Application>().contentResolver, uri)
        } catch (_: Exception) {
            // Provider may not support deletion; nothing more we can do.
        }
    }

    fun startBatchProcessing(destinationDirUri: Uri) {
        isProcessing = true

        viewModelScope.launch {
            val failures = mutableListOf<String>()

            // Read base games' embedded titles first, so updates/DLC in the same batch
            // are named after their game regardless of selection order.
            statusMessage = "Reading game titles..."
            for (uri in batchQueue) {
                val info = titleInfo(uri)
                if (info?.kind == TitleInfo.Kind.GAME) romTitle(uri, info)
            }

            for (i in batchQueue.indices) {
                currentBatchIndex = i
                val inputUri = batchQueue[i]
                ciaFileUri   = inputUri
                currentSmdh  = null

                val originalName = getFileName(inputUri) ?: "game.cia"
                val info      = titleInfo(inputUri)
                val cci       = wantsCci(info)
                val finalName = outputName(originalName, info, romTitle(inputUri, info))
                currentSmdh   = smdh(inputUri)

                statusMessage = "Processing batch (${i + 1}/${batchQueue.size}): $originalName"

                val outUri = withContext(Dispatchers.IO) {
                    DocumentFile.fromTreeUri(getApplication(), destinationDirUri)
                        ?.createFile("application/octet-stream", finalName)?.uri
                }
                if (outUri == null) {
                    failures += "$originalName: could not create output file"
                    continue
                }

                val error = runDecrypt(inputUri, outUri, cci) { status ->
                    statusMessage = "Batch [${i + 1}/${batchQueue.size}] $status"
                }
                if (error != null) failures += "$originalName: $error"
            }

            val total = batchQueue.size
            isProcessing = false
            statusMessage = if (failures.isEmpty()) {
                "Batch complete! $total/$total succeeded."
            } else {
                "Batch finished: ${total - failures.size}/$total succeeded.\nFailed:\n" +
                        failures.joinToString("\n")
            }
            batchQueue    = emptyList()
        }
    }

    // --- Helpers ---

    private fun getFileName(uri: Uri): String? {
        if (uri.scheme == "content") {
            getApplication<Application>().contentResolver.query(uri, null, null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx != -1) return cursor.getString(idx)
                    }
                }
        }
        val path = uri.path ?: return null
        val cut  = path.lastIndexOf('/')
        return if (cut != -1) path.substring(cut + 1) else path
    }

    private fun prefs() =
        getApplication<Application>().getSharedPreferences("prefs", Context.MODE_PRIVATE)
}
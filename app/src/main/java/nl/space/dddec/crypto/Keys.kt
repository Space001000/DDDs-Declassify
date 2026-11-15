package nl.space.dddec.crypto

/**
 * Key lookup. The app ships no key material: every key comes from an aes_keys.txt
 * file the user dumps from their own console.
 */
object Keys {
    fun getKey(name: String, store: KeyStore): ByteArray? =
        store.get(name)?.let { CryptoUtils.hexToBytes(it) }
}

/**
 * Holds keys loaded at runtime from a user-supplied aes_keys.txt file.
 *
 * Expected format (same as Citra / Azahar):
 *   generator=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 *   slot0x2CKeyX=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 *   slot0x3DKeyX=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 *   common0=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX      (KeyY for keyslot 0x3D, indices 0-5)
 *
 * Optionally, a pre-scrambled normal key can be given directly as common_key_N=...
 *
 * Lines starting with '#' or ';' are comments. Key names are case-insensitive.
 */
class KeyStore private constructor(private val keys: Map<String, String>) {

    fun get(name: String): String? = keys[name.lowercase()]

    /**
     * Returns the normal key used to decrypt ticket title keys for the given common key index.
     * Prefers an explicit common_key_N normal key; otherwise derives it from
     * slot0x3DKeyX and the commonN KeyY using the key scrambler.
     */
    fun commonKey(index: Int): ByteArray? {
        get("common_key_$index")?.let { return CryptoUtils.hexToBytes(it) }
        val keyX = get("slot0x3DKeyX") ?: return null
        val keyY = get("common$index") ?: return null
        return CryptoUtils.scrambleKey(
            CryptoUtils.hexToBytes(keyX),
            CryptoUtils.hexToBytes(keyY),
            this
        )
    }

    /** True when the file contains at least the scrambler constant and the base NCCH KeyX. */
    val isUsable: Boolean get() = get("generator") != null && get("slot0x2CKeyX") != null
    val keyCount: Int     get() = keys.size

    /** Names of keys the basic decryption path needs but which are absent. */
    fun missingEssentials(): List<String> =
        listOf("generator", "slot0x2CKeyX").filter { get(it) == null }

    companion object {
        fun parse(text: String): KeyStore {
            val map = mutableMapOf<String, String>()
            for (raw in text.lines()) {
                val line = raw.trim()
                if (line.startsWith('#') || line.startsWith(';') || line.isEmpty()) continue
                val eq = line.indexOf('=')
                if (eq < 1) continue
                val name  = line.substring(0, eq).trim().lowercase()
                val value = line.substring(eq + 1).trim().uppercase()
                if (value.length == 32 && value.all { it.isDigit() || it in 'A'..'F' }) {
                    map[name] = value
                }
            }
            return KeyStore(map)
        }

        fun empty() = KeyStore(emptyMap())
    }
}

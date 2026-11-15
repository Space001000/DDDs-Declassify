package nl.space.dddec.crypto

import nl.space.dddec.model.TitleInfo

object FileNameUtils {

    /**
     * Cleans a CIA filename (logic based on my PowerShell ROM name cleaner) and suggests an
     * output name with a "(Decrypted)" suffix.
     *
     * When [info] is known, the title type is added so a base game, its update and its DLC —
     * which are often named identically — never produce the same output name:
     *   "Game (Decrypted).cia", "Game (Update v1.2.0) (Decrypted).cia", "Game (DLC) (Decrypted).cia"
     */
    fun cleanAndSuggest(originalName: String, info: TitleInfo? = null, romTitle: String? = null): String {
        val lastDotIndex = originalName.lastIndexOf('.')
        val extension = if (lastDotIndex != -1) originalName.substring(lastDotIndex + 1) else "cia"
        // Prefer the title embedded in the game itself (SMDH); the filename is only a fallback.
        val embedded = romTitle?.let { sanitize(it) }?.takeIf { it.isNotBlank() }
        var name = embedded
            ?: if (lastDotIndex != -1) originalName.substring(0, lastDotIndex) else originalName

        // 1. Leading 16-hex-digit Title ID (e.g. "0004000000086400 Game Name")
        name = name.replace(Regex("^[0-9A-Fa-f]{16}[ _-]+"), "")

        // 2. Leading catalogue/collection number (e.g. "0001 - Game", "AB0001 - Game")
        name = name.replace(Regex("^[A-Z0-9]{0,4}[0-9]{3,5} - "), "")

        // 3. Product code (e.g. " (CTR-P-XXXX)")
        name = name.replace(Regex(" ?\\((?:CTR|KTR)-[A-Z0-9-]+\\)"), "")

        // 4. Version tag (e.g. " (v1.0.2)") — re-added below for updates from the real TMD version
        name = name.replace(Regex(" ?\\(v[0-9.]+\\)", RegexOption.IGNORE_CASE), "")

        // 5. Region tags (e.g. " (USA)", "(E)", " (Europe)")
        name = name.replace(
            Regex(" ?\\((?:U|E|J|W|K|USA|EUR|JPN|KOR|Europe|Japan|World)\\)", RegexOption.IGNORE_CASE), ""
        )

        // 6. Content-type tags that we re-add consistently from the Title ID
        name = name.replace(
            Regex(" ?[(\\[](?:Update|Patch|DLC|Demo)[^)\\]]*[)\\]]", RegexOption.IGNORE_CASE), ""
        )

        // 7. Trailing lowercase dot-tags added by dumping/conversion tools (e.g. "Game.standard")
        name = name.replace(Regex("(?:\\.[a-z]+)+$"), "")

        // 8. Existing decryption markers
        name = name.replace(Regex(" ?\\(Decrypted\\)", RegexOption.IGNORE_CASE), "")
        name = name.replace(Regex("[ _-]decrypted$", RegexOption.IGNORE_CASE), "")

        // 9. Whitespace
        name = name.replace(Regex("\\s+"), " ").trim()
        if (name.isEmpty()) name = info?.titleIdHex ?: "game"

        val typeTag = when (info?.kind) {
            TitleInfo.Kind.UPDATE -> " (Update v${info.versionString})"
            TitleInfo.Kind.DLC    -> " (DLC)"
            TitleInfo.Kind.DEMO   -> " (Demo)"
            else                  -> ""
        }
        return "$name$typeTag (Decrypted).$extension"
    }

    /** Makes an embedded title safe as a filename (SMDH titles can contain newlines, ':' etc.). */
    fun sanitize(title: String): String =
        title.replace(Regex("[\\r\\n\\t]+"), " ")
            .replace(Regex(" ?: ?"), " - ")
            .replace(Regex("[\\\\/*?\"<>|]"), "")
            .replace(Regex("\\s+"), " ")
            .trim()
            .take(120)
}

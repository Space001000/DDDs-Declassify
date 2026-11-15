package nl.space.dddec.crypto

object FileNameUtils {

    /**
     * Cleans the filename using logic similar to the PowerShell Rom Name Cleaner script
     * and suggests a new name with a "(Decrypted)" suffix.
     */
    fun cleanAndSuggest(originalName: String): String {
        // Extract extension and base name
        val lastDotIndex = originalName.lastIndexOf('.')
        val extension = if (lastDotIndex != -1) originalName.substring(lastDotIndex + 1) else "cia"
        var name = if (lastDotIndex != -1) originalName.substring(0, lastDotIndex) else originalName

        // 1. Remove 16-char Title ID prefix (e.g., "0004000000086400 Game Name")
        name = name.replace(Regex("^[0-9A-F]{16} "), "")

        // 2. Remove Scene release prefix (e.g., "3DS0001 - Game Name")
        name = name.replace(Regex("^3DS[0-9]{4} - "), "")

        // 3. Remove Product Code (e.g., " (CTR-P-XXXX)")
        name = name.replace(Regex(" \\(CTR-[A-Z0-9-]+\\)"), "")

        // 4. Remove Version tag (e.g., " (v1.0.2)")
        name = name.replace(Regex(" \\(v[0-9.]+\\)"), "")

        // 5. Remove Region tags (e.g., " (USA)", " (E)", "(W)")
        // Supports both " (USA)" and "(USA)"
        name = name.replace(Regex(" ?\\((U|E|W|J|USA|EUR|JPN)\\)"), "")

        // 6. Remove technical tags
        name = name.replace(".piratelegit", "", ignoreCase = true)
        name = name.replace(".standard", "", ignoreCase = true)

        // 7. Remove existing decryption tags to avoid duplication
        name = name.replace("-decrypted", "", ignoreCase = true)
        name = name.replace(" Decrypted", "", ignoreCase = true)

        // 8. Clean up whitespace
        name = name.trim()

        // 9. Suggest output name with (Decrypted) suffix
        return "$name (Decrypted).$extension"
    }
}

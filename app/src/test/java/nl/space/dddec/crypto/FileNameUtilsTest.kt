package nl.space.dddec.crypto

import nl.space.dddec.model.TitleInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class FileNameUtilsTest {

    private val game   = TitleInfo(0x0004000000055D00L, 0)
    private val update = TitleInfo(0x0004000E00055D00L, (1 shl 10) or (5 shl 4))   // v1.5.0
    private val dlc    = TitleInfo(0x0004008C00055D00L, 0)

    @Test fun cleansFilenameTags() {
        assertEquals(
            "Pokemon X (Decrypted).cia",
            FileNameUtils.cleanAndSuggest("0004000000055D00 Pokemon X (USA) (CTR-P-EKJA) (v1.0.0).standard.cia")
        )
        assertEquals("Some Game (Decrypted).cia", FileNameUtils.cleanAndSuggest("3DS0001 - Some Game (E).cia"))
        assertEquals("Some Game (Decrypted).cia", FileNameUtils.cleanAndSuggest("Some Game-decrypted.cia"))
    }

    @Test fun sameFilenameForGameUpdateDlcGivesDistinctOutputs() {
        val name = "Pokemon X (USA).cia"
        val a = FileNameUtils.cleanAndSuggest(name, game)
        val b = FileNameUtils.cleanAndSuggest(name, update)
        val c = FileNameUtils.cleanAndSuggest(name, dlc)
        assertEquals("Pokemon X (Decrypted).cia", a)
        assertEquals("Pokemon X (Update v1.5.0) (Decrypted).cia", b)
        assertEquals("Pokemon X (DLC) (Decrypted).cia", c)
        assertNotEquals(a, b); assertNotEquals(b, c)
    }

    @Test fun existingTypeTagIsNotDuplicated() {
        assertEquals(
            "Pokemon X (Update v1.5.0) (Decrypted).cia",
            FileNameUtils.cleanAndSuggest("Pokemon X (Update) (v1.5).cia", update)
        )
    }

    @Test fun embeddedTitleWinsAndIsSanitized() {
        assertEquals(
            "Zelda - A Link Between Worlds (Decrypted).cia",
            FileNameUtils.cleanAndSuggest("random_dump_123.cia", game, "Zelda: A Link\nBetween Worlds")
        )
    }

    @Test fun blankEmbeddedTitleFallsBackToFilename() {
        assertEquals("My Game (Decrypted).cia", FileNameUtils.cleanAndSuggest("My Game.cia", game, "  "))
    }
}

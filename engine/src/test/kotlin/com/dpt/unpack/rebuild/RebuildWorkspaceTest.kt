package com.dpt.unpack.rebuild

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class RebuildWorkspaceTest {

    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `create initializes workspace structure`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-1")
        val result = ws.prepare()
        assertTrue(result.isSuccess)
        assertTrue(ws.inputDir.isDirectory)
        assertTrue(ws.patchedDir.isDirectory)
        assertTrue(ws.manifestDir.isDirectory)
        assertTrue(ws.outputDir.isDirectory)
        assertTrue(ws.tempDir.isDirectory)
    }

    @Test
    fun `stageApk copies file correctly`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-2")
        ws.prepare()

        val source = tempDir.resolve("source.apk").toFile()
        source.writeBytes(byteArrayOf(0x50, 0x4B, 0x03, 0x04))

        val staged = ws.stageApk(source)
        assertTrue(staged.isSuccess)
        assertTrue(ws.inputApk().exists())
        assertArrayEquals(source.readBytes(), ws.inputApk().readBytes())
    }

    @Test
    fun `stageDex copies file correctly`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-3")
        ws.prepare()

        val dex = createMinimalDex("classes.dex")
        val staged = ws.stageDex(dex)
        assertTrue(staged.isSuccess)
        assertTrue(ws.patchedDir.resolve("classes.dex").exists())
    }

    @Test
    fun `stageDex bytes creates file correctly`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-4")
        ws.prepare()

        val dexBytes = createMinimalDexBytes()
        val staged = ws.stageDex("classes.dex", dexBytes)
        assertTrue(staged.isSuccess)
        assertArrayEquals(dexBytes, ws.patchedDir.resolve("classes.dex").readBytes())
    }

    @Test
    fun `stageManifest writes bytes correctly`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-5")
        ws.prepare()

        val manifest = byteArrayOf(0x03, 0x00, 0x08, 0x00)
        val staged = ws.stageManifest(manifest)
        assertTrue(staged.isSuccess)
        assertArrayEquals(manifest, ws.manifestFile().readBytes())
    }

    @Test
    fun `listStagedDex returns sorted order`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-6")
        ws.prepare()

        ws.stageDex("classes3.dex", createMinimalDexBytes())
        ws.stageDex("classes.dex", createMinimalDexBytes())
        ws.stageDex("classes2.dex", createMinimalDexBytes())

        val dexFiles = ws.listStagedDex()
        assertEquals(3, dexFiles.size)
        assertEquals("classes.dex", dexFiles[0].name)
        assertEquals("classes2.dex", dexFiles[1].name)
        assertEquals("classes3.dex", dexFiles[2].name)
    }

    @Test
    fun `cleanTemp removes temp files`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-7")
        ws.prepare()

        ws.tempDir.resolve("temp.txt").writeText("temp")
        assertTrue(ws.tempDir.resolve("temp.txt").exists())

        ws.cleanTemp()
        assertFalse(ws.tempDir.resolve("temp.txt").exists())
    }

    @Test
    fun `destroy removes entire workspace`() {
        val ws = RebuildWorkspace.create(tempDir.toFile(), "test-8")
        ws.prepare()
        ws.inputDir.resolve("test.txt").writeText("test")

        ws.destroy()
        assertFalse(ws.rootDir.exists())
    }

    private fun createMinimalDex(name: String): File {
        val file = tempDir.resolve(name).toFile()
        file.writeBytes(createMinimalDexBytes())
        return file
    }

    private fun createMinimalDexBytes(): ByteArray {
        val dex = ByteArray(112)
        dex[0] = 0x64; dex[1] = 0x65; dex[2] = 0x78; dex[3] = 0x0A
        dex[4] = 0x30; dex[5] = 0x33; dex[6] = 0x35; dex[7] = 0x00
        dex[32] = 0x70; dex[33] = 0x00; dex[34] = 0x00; dex[35] = 0x00
        return com.dpt.unpack.checksum.DexChecksum.fix(dex)
    }
}

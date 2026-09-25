package com.dpt.unpack.app

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.dpt.unpack.detection.DptDetector
import java.io.File
import java.util.concurrent.Executors

class MainActivity : Activity() {

    private lateinit var tabInstalled: TextView
    private lateinit var tabStorage: TextView
    private lateinit var installedTab: LinearLayout
    private lateinit var storageTab: LinearLayout

    private lateinit var searchInput: EditText
    private lateinit var sectionLabel: TextView
    private lateinit var appList: RecyclerView
    private lateinit var loadingState: LinearLayout
    private lateinit var emptyState: LinearLayout
    private lateinit var emptyText: TextView

    private lateinit var apkEmptyState: LinearLayout
    private lateinit var apkSelectedState: LinearLayout
    private lateinit var btnPick: TextView
    private lateinit var btnUnpack: TextView
    private lateinit var btnChange: TextView
    private lateinit var pickedName: TextView
    private lateinit var pickedSize: TextView
    private lateinit var pickedPackage: TextView
    private lateinit var apkIcon: ImageView

    private lateinit var progressSection: LinearLayout
    private lateinit var progress: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var resultSection: LinearLayout
    private lateinit var resultIcon: ImageView
    private lateinit var resultTitle: TextView
    private lateinit var resultMessage: TextView
    private lateinit var unpackResult: TextView
    private lateinit var unpackCopyHint: TextView
    private lateinit var btnInstall: TextView
    private lateinit var protectionSection: LinearLayout
    private lateinit var protectionList: TextView
    private lateinit var logSection: LinearLayout
    private lateinit var logToggle: LinearLayout
    private lateinit var logView: TextView
    private lateinit var logCount: TextView

    private lateinit var appListAdapter: AppListAdapter
    private val executor = Executors.newSingleThreadExecutor()

    private var pickedUri: Uri? = null
    private var pickName: String? = null
    private var currentStrategy: String? = null
    private var currentInput: File? = null
    private var currentOutputBase: String? = null
    private var busy = false
    private var logsExpanded = false
    private val logLines = mutableListOf<String>()
    private var activeTab = TAB_INSTALLED

    private val pickRequest = 1001
    private val storageRequest = 2001
    private val installResultFilter = "com.dpt.unpack.app.INSTALL_RESULT"

    private var lastOutputPath: String? = null
    private var lastOutputApk: File? = null

    private val installReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != installResultFilter) return
            val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)
            val message = when (status) {
                PackageInstaller.STATUS_SUCCESS -> "APK installed"
                PackageInstaller.STATUS_PENDING_USER_ACTION -> "Confirm the install on your screen"
                else -> intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "Install failed ($status)"
            }
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }
    }

    private var resumedOnce = false
    private var loadingApps = false

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val action = intent?.action
            if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
                if (intent?.data?.schemeSpecificPart != packageName) reloadInstalledApps()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bindViews()
        setupTabs()
        setupSearch()
        setupStorageTab()
        setupRecyclerView()

        if (savedInstanceState != null) {
            activeTab = savedInstanceState.getInt("activeTab", TAB_INSTALLED)
        }
        switchTab(activeTab)
        loadInstalledApps()
        ContextCompat.registerReceiver(
            this, installReceiver, IntentFilter(installResultFilter), ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("activeTab", activeTab)
    }

    override fun onResume() {
        super.onResume()
        ContextCompat.registerReceiver(
            this,
            packageReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            },
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        if (resumedOnce) reloadInstalledApps()
        resumedOnce = true
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(packageReceiver) }
    }

    private fun bindViews() {
        tabInstalled = findViewById(R.id.tabInstalled)
        tabStorage = findViewById(R.id.tabStorage)
        installedTab = findViewById(R.id.installedTab)
        storageTab = findViewById(R.id.storageTab)

        searchInput = findViewById(R.id.searchInput)
        sectionLabel = findViewById(R.id.sectionLabel)
        appList = findViewById(R.id.appList)
        loadingState = findViewById(R.id.loadingState)
        emptyState = findViewById(R.id.emptyState)
        emptyText = findViewById(R.id.emptyText)

        apkEmptyState = findViewById(R.id.apkEmptyState)
        apkSelectedState = findViewById(R.id.apkSelectedState)
        btnPick = findViewById(R.id.btnPick)
        btnUnpack = findViewById(R.id.btnUnpack)
        btnChange = findViewById(R.id.btnChange)
        pickedName = findViewById(R.id.pickedName)
        pickedSize = findViewById(R.id.pickedSize)
        pickedPackage = findViewById(R.id.pickedPackage)
        apkIcon = findViewById(R.id.apkIcon)

        progressSection = findViewById(R.id.progressSection)
        progress = findViewById(R.id.progress)
        statusText = findViewById(R.id.statusText)
        resultSection = findViewById(R.id.resultSection)
        resultIcon = findViewById(R.id.resultIcon)
        resultTitle = findViewById(R.id.resultTitle)
        resultMessage = findViewById(R.id.resultMessage)
        unpackResult = findViewById(R.id.unpackResult)
        unpackCopyHint = findViewById(R.id.unpackCopyHint)
        btnInstall = findViewById(R.id.btnInstall)
        protectionSection = findViewById(R.id.protectionSection)
        protectionList = findViewById(R.id.protectionList)
        logSection = findViewById(R.id.logSection)
        logToggle = findViewById(R.id.logToggle)
        logView = findViewById(R.id.logView)
        logCount = findViewById(R.id.logCount)
    }

    private fun setupTabs() {
        tabInstalled.setOnClickListener { switchTab(TAB_INSTALLED) }
        tabStorage.setOnClickListener { switchTab(TAB_STORAGE) }
    }

    private fun switchTab(tab: Int) {
        activeTab = tab
        if (tab == TAB_INSTALLED) {
            tabInstalled.setBackgroundResource(R.drawable.glass_pill_selected)
            tabInstalled.setTextColor(getColor(R.color.textPrimary))
            tabStorage.setBackgroundResource(android.R.color.transparent)
            tabStorage.setTextColor(getColor(R.color.textSecondary))
            installedTab.visibility = View.VISIBLE
            storageTab.visibility = View.GONE
        } else {
            tabStorage.setBackgroundResource(R.drawable.glass_pill_selected)
            tabStorage.setTextColor(getColor(R.color.textPrimary))
            tabInstalled.setBackgroundResource(android.R.color.transparent)
            tabInstalled.setTextColor(getColor(R.color.textSecondary))
            storageTab.visibility = View.VISIBLE
            installedTab.visibility = View.GONE
        }
    }

    private fun setupSearch() {
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                appListAdapter.filter(s?.toString() ?: "")
                updateSectionLabel()
                updateEmptyState()
            }
            override fun afterTextChanged(s: Editable?) {}
        })
        searchInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEARCH) {
                searchInput.clearFocus()
                true
            } else false
        }
    }

    private fun setupStorageTab() {
        btnPick.setOnClickListener { pickApk() }
        btnChange.setOnClickListener { pickApk() }
        btnUnpack.setOnClickListener { startUnpack() }
        unpackResult.setOnClickListener { copyToClipboard() }
        btnInstall.setOnClickListener { installLastApk() }
        logToggle.setOnClickListener { toggleLogs() }
    }

    private fun setupRecyclerView() {
        appListAdapter = AppListAdapter { app -> dumpInstalledApp(app) }
        appList.layoutManager = LinearLayoutManager(this)
        appList.adapter = appListAdapter
    }

    // ── Installed Apps ──

    private fun loadInstalledApps() {
        loadingApps = true
        loadingState.visibility = View.VISIBLE
        emptyState.visibility = View.GONE
        sectionLabel.text = getString(R.string.section_dpt) + " • —"

        executor.execute {
            try {
                val pm = packageManager
                val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                val myPkg = packageName

                val apps = packages
                    .filter { it.packageName != myPkg }
                    .mapNotNull { info ->
                        val apkPath = try {
                            val pi = pm.getPackageInfo(info.packageName, PackageManager.GET_ACTIVITIES)
                            pi.applicationInfo?.sourceDir
                        } catch (_: Exception) { null }
                            ?: return@mapNotNull null
                        if (!isDptPacked(apkPath)) return@mapNotNull null

                        val label = pm.getApplicationLabel(info).toString()
                        val version = try {
                            val pi = pm.getPackageInfo(info.packageName, 0)
                            pi.versionName ?: ""
                        } catch (_: Exception) { "" }

                        val hasSplits = try {
                            val pi = pm.getPackageInfo(info.packageName, PackageManager.GET_ACTIVITIES)
                            pi.applicationInfo?.splitSourceDirs?.isNotEmpty() == true
                        } catch (_: Exception) { false }

                        val icon = try {
                            pm.getApplicationIcon(info)
                        } catch (_: Exception) { null }

                        AppListAdapter.InstalledApp(
                            label = label,
                            packageName = info.packageName,
                            versionName = version,
                            icon = icon,
                            isSystem = (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                            apkPath = apkPath,
                            hasSplits = hasSplits,
                        )
                    }
                    .sortedWith(compareBy<AppListAdapter.InstalledApp> { !it.isSystem }.thenBy { it.label.lowercase() })

                runOnUiThread {
                    loadingApps = false
                    loadingState.visibility = View.GONE
                    appListAdapter.submitList(apps)
                    updateSectionLabel()
                    updateEmptyState()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    loadingApps = false
                    loadingState.visibility = View.GONE
                    emptyState.visibility = View.VISIBLE
                    emptyText.text = getString(R.string.error_loading)
                }
            }
        }
    }

    private fun reloadInstalledApps() {
        if (loadingApps) return
        loadInstalledApps()
    }

    private fun isDptPacked(apkPath: String): Boolean =
        try { DptDetector.detect(File(apkPath)).detected } catch (_: Exception) { false }

    private fun updateSectionLabel() {
        val count = appListAdapter.getFilteredCount()
        sectionLabel.text = getString(R.string.section_dpt) + " • $count"
    }

    private fun updateEmptyState() {
        val count = appListAdapter.getFilteredCount()
        if (count == 0 && loadingState.visibility != View.VISIBLE) {
            emptyState.visibility = View.VISIBLE
            emptyText.text = if (query.isEmpty()) getString(R.string.no_apps) else getString(R.string.no_results)
        } else {
            emptyState.visibility = View.GONE
        }
    }

    private val query: String get() = searchInput.text?.toString()?.trim() ?: ""

    private fun dumpInstalledApp(app: AppListAdapter.InstalledApp) {
        if (busy) return
        if (app.apkPath == null) {
            resultSection.visibility = View.VISIBLE
            resultIcon.setImageResource(R.drawable.ic_error)
            resultTitle.text = getString(R.string.result_failed)
            resultMessage.text = "Cannot resolve APK path for ${app.packageName}"
            return
        }

        if (app.hasSplits) {
            resultSection.visibility = View.VISIBLE
            resultIcon.setImageResource(R.drawable.ic_warning)
            resultTitle.text = "Split APK detected"
            resultMessage.text = "${app.packageName} has split APKs. Only the base APK will be analyzed. Full unpacking of split APKs is not yet supported."
        }

        switchTab(TAB_STORAGE)
        pickedUri = null
        pickName = "${app.label}.apk"
        val file = File(app.apkPath)
        pickedName.text = app.label
        pickedSize.text = formatSize(file.length())
        pickedPackage.text = app.packageName
        apkIcon.setImageDrawable(app.icon)
        apkEmptyState.visibility = View.GONE
        apkSelectedState.visibility = View.VISIBLE
        currentInput = file
        currentOutputBase = sanitizeFileName(app.label) + "-unpacked"
        hideResults()
        startCheckFromFile(file)
    }

    // ── From Storage ──

    private fun pickApk() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf(
                "application/vnd.android.package-archive",
                "application/octet-stream",
                "application/zip",
            ))
        }
        startActivityForResult(intent, pickRequest)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == pickRequest && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            pickedUri = uri
            pickName = queryName(uri)
            hideResults()
            startCheck(uri)
        }
    }

    private fun queryName(uri: Uri): String {
        var name = "APK"
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) name = c.getString(idx)
        }
        return name
    }

    private fun startCheck(uri: Uri) {
        if (busy) return
        busy = true
        showApkSelected()
        btnUnpack.visibility = View.GONE
        progressSection.visibility = View.VISIBLE
        progress.isIndeterminate = true
        statusText.text = getString(R.string.progress_analyzing)

        executor.execute {
            try {
                val tmpFile = File(cacheDir, "picked_$pickName")
                contentResolver.openInputStream(uri)?.use { input ->
                    tmpFile.outputStream().use { output -> input.copyTo(output) }
                }
                val strategy = checkDpt(tmpFile)
                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showDptStatus(strategy != null)
                    if (strategy != null) {
                        currentInput = tmpFile
                        currentOutputBase = sanitizeFileName(pickName?.removeSuffix(".apk") ?: "app") + "-unpacked"
                        currentStrategy = strategy
                        btnUnpack.visibility = View.VISIBLE
                    } else {
                        btnUnpack.visibility = View.GONE
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showResult(false, "Analysis failed: ${e.message}")
                }
            }
        }
    }

    private fun startCheckFromFile(file: File) {
        if (busy) return
        busy = true
        btnUnpack.visibility = View.GONE
        progressSection.visibility = View.VISIBLE
        progress.isIndeterminate = true
        statusText.text = getString(R.string.progress_analyzing)

        executor.execute {
            try {
                val strategy = checkDpt(file)
                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showDptStatus(strategy != null)
                    if (strategy != null) {
                        currentStrategy = strategy
                        btnUnpack.visibility = View.VISIBLE
                    } else {
                        btnUnpack.visibility = View.GONE
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showResult(false, "Analysis failed: ${e.message}")
                }
            }
        }
    }

    private fun checkDpt(file: File): String? =
        if (DptDetector.detect(file).detected) "dpt" else null

    private fun startUnpack() {
        if (busy || currentInput == null || currentStrategy == null) return
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
            checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), storageRequest)
            return
        }
        busy = true
        btnUnpack.visibility = View.GONE
        btnInstall.visibility = View.GONE
        unpackCopyHint.visibility = View.GONE
        progressSection.visibility = View.VISIBLE
        progress.isIndeterminate = true
        resultSection.visibility = View.GONE
        logLines.clear()
        logView.text = ""
        logSection.visibility = View.VISIBLE
        logCount.text = "0"
        logsExpanded = false
        logView.visibility = View.GONE

        executor.execute {
            try {
                val strategy = currentStrategy!!
                val input = currentInput!!
                val outDir = File(cacheDir, "${input.nameWithoutExtension}_unpacked")
                val keystore = ensureKeystore()

                runOnUiThread { statusText.text = getString(R.string.progress_unpacking) }
                log("Strategy: $strategy")
                log("Input: ${input.absolutePath}")
                android.util.Log.d("Unpack", "Starting unpack: strategy=$strategy input=${input.absolutePath} size=${input.length()}")

                val result = UnpackOrchestrator.unpack(
                    input, outDir, strategy, keystore,
                    { line ->
                        android.util.Log.d("Unpack", line)
                        runOnUiThread { log(line) }
                    },
                    outputBaseName = currentOutputBase
                )

                val saved = saveToDownloads(result.finalApk)
                lastOutputPath = saved
                lastOutputApk = result.finalApk

                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showResult(true, "Unpacked successfully in ${result.elapsed}ms")
                    unpackResult.visibility = View.VISIBLE
                    unpackResult.text = saved
                    unpackCopyHint.visibility = View.VISIBLE
                    btnInstall.visibility = View.VISIBLE
                    btnUnpack.visibility = View.VISIBLE
                }
            } catch (e: Exception) {
                android.util.Log.e("Unpack", "Unpack failed", e)
                runOnUiThread {
                    progressSection.visibility = View.GONE
                    busy = false
                    showResult(false, "Unpack failed: ${e.message}")
                    unpackResult.visibility = View.GONE
                    unpackCopyHint.visibility = View.GONE
                    btnInstall.visibility = View.GONE
                    btnUnpack.visibility = View.VISIBLE
                }
            }
        }
    }

    // ── UI Helpers ──

    private fun showApkSelected() {
        apkEmptyState.visibility = View.GONE
        apkSelectedState.visibility = View.VISIBLE
        pickedName.text = pickName ?: "APK"
        pickedSize.text = "—"
        pickedPackage.text = "—"
    }

    private fun hideResults() {
        progressSection.visibility = View.GONE
        resultSection.visibility = View.GONE
        protectionSection.visibility = View.GONE
        logSection.visibility = View.GONE
        unpackResult.visibility = View.GONE
        unpackCopyHint.visibility = View.GONE
    }

    private fun showResult(success: Boolean, message: String) {
        resultSection.visibility = View.VISIBLE
        if (success) {
            resultIcon.setImageResource(R.drawable.ic_check_circle)
            resultTitle.text = getString(R.string.result_success)
            resultTitle.setTextColor(getColor(R.color.success))
        } else {
            resultIcon.setImageResource(R.drawable.ic_error)
            resultTitle.text = getString(R.string.result_failed)
            resultTitle.setTextColor(getColor(R.color.error))
        }
        resultMessage.text = message
    }

    private fun showDptStatus(detected: Boolean) {
        protectionSection.visibility = View.VISIBLE
        protectionList.text = if (detected) "DPT Shell detected" else "Not a DPT-packed APK"
    }

    private fun saveToDownloads(apk: File): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, apk.name)
                put(MediaStore.MediaColumns.MIME_TYPE, "application/vnd.android.package-archive")
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/DPT-Unpacked")
            }
            val uri = contentResolver.insert(
                MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), values
            ) ?: throw IllegalStateException("could not create Downloads entry")
            contentResolver.openOutputStream(uri)?.use { out ->
                apk.inputStream().use { it.copyTo(out) }
            } ?: throw IllegalStateException("could not write to Downloads")
            return File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                "DPT-Unpacked"
            ).resolve(apk.name).absolutePath
        }
        val dir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            "DPT-Unpacked"
        )
        if (!dir.exists()) dir.mkdirs()
        val dest = File(dir, apk.name)
        apk.copyTo(dest, overwrite = true)
        return dest.absolutePath
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == storageRequest) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startUnpack()
            } else {
                showResult(false, "Storage permission required to save to Downloads")
            }
        }
    }

    private fun ensureKeystore(): File {
        val f = File(filesDir, "appkey.p12")
        if (!f.exists()) {
            assets.open("appkey.p12").use { input ->
                f.outputStream().use { output -> input.copyTo(output) }
            }
        }
        return f
    }

    private fun copyToClipboard() {
        val path = lastOutputPath ?: return
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("output path", path))
        Toast.makeText(this, "Path copied to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun installLastApk() {
        val apk = lastOutputApk ?: return
        // Android 8+: installing APKs from an app requires the "Allow from this source"
        // toggle under Settings → Apps → Unpacker → Install unknown apps.
        if (!packageManager.canRequestPackageInstalls()) {
            runCatching {
                startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:$packageName")
                    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }
            Toast.makeText(
                this,
                "Enable \"Allow from this source\" for Unpacker, then press Install again.",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        try {
            val sessionParams = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            val sessionId = packageManager.packageInstaller.createSession(sessionParams)
            val session = packageManager.packageInstaller.openSession(sessionId)
            val out = session.openWrite("pkg", 0, apk.length())
            val buf = ByteArray(8192)
            apk.inputStream().use { input ->
                var r: Int
                while (input.read(buf).also { r = it } >= 0) out.write(buf, 0, r)
            }
            session.fsync(out)
            out.close()
            val pi = PendingIntent.getBroadcast(
                this, 42, Intent(installResultFilter).setPackage(packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            session.commit(pi.intentSender)
            session.close()
            Toast.makeText(this, "Installing unpacked APK…", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            android.util.Log.e("Install", "install failed", e)
            Toast.makeText(
                this,
                "Install failed: ${e.message}. Note: the original DPT app must be uninstalled first (signature mismatch).",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun toggleLogs() {
        logsExpanded = !logsExpanded
        logView.visibility = if (logsExpanded) View.VISIBLE else View.GONE
    }

    private fun log(line: String) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            logLines.add(line)
            logView.text = logLines.joinToString("\n")
            logCount.text = "${logLines.size}"
        } else {
            runOnUiThread { log(line) }
        }
    }

    private fun formatSize(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return "%.1f KB".format(kb)
        val mb = kb / 1024.0
        if (mb < 1024) return "%.1f MB".format(mb)
        return "%.2f GB".format(mb / 1024.0)
    }

    private fun sanitizeFileName(name: String): String {
        val cleaned = name
            .replace(Regex("[\\\\/:*?\"<>|\\p{Cntrl}]"), "_")
            .trim()
            .trimEnd('.')
            .trim()
        return cleaned.ifBlank { "app" }.take(60)
    }

    companion object {
        private const val TAB_INSTALLED = 0
        private const val TAB_STORAGE = 1
    }
}
package com.dpt.unpack.app

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class AppListAdapter(
    private val onDump: (InstalledApp) -> Unit,
) : RecyclerView.Adapter<AppListAdapter.ViewHolder>() {

    data class InstalledApp(
        val label: String,
        val packageName: String,
        val versionName: String,
        val icon: Drawable?,
        val isSystem: Boolean,
        val apkPath: String?,
        val hasSplits: Boolean,
    )

    private var items: List<InstalledApp> = emptyList()
    private var filtered: List<InstalledApp> = emptyList()
    private var query: String = ""

    fun submitList(list: List<InstalledApp>) {
        items = list
        applyFilter()
    }

    fun filter(q: String) {
        query = q.trim().lowercase()
        applyFilter()
    }

    private fun applyFilter() {
        filtered = if (query.isEmpty()) items
        else items.filter {
            it.label.lowercase().contains(query) || it.packageName.lowercase().contains(query)
        }
        notifyDataSetChanged()
    }

    fun getFilteredCount(): Int = filtered.size

    override fun getItemCount(): Int = filtered.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false)
        return ViewHolder(v)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val app = filtered[position]
        holder.bind(app)
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val icon: ImageView = view.findViewById(R.id.appIcon)
        private val name: TextView = view.findViewById(R.id.appName)
        private val pkg: TextView = view.findViewById(R.id.appPackage)
        private val badge: LinearLayout = view.findViewById(R.id.protectionBadge)
        private val badgeText: TextView = view.findViewById(R.id.protectionText)
        private val badgeIcon: ImageView = view.findViewById(R.id.protectionIcon)
        private val dumpBtn: TextView = view.findViewById(R.id.btnDump)

        fun bind(app: InstalledApp) {
            name.text = app.label
            pkg.text = app.packageName
            if (app.icon != null) {
                icon.setImageDrawable(app.icon)
            } else {
                icon.setImageResource(android.R.drawable.sym_def_app_icon)
            }
            badge.visibility = View.GONE
            dumpBtn.setOnClickListener { onDump(app) }
        }
    }
}

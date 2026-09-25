pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("org.jetbrains.kotlin.jvm") version "2.1.20"
        id("org.jetbrains.kotlin.android") version "2.1.20"
        id("com.android.application") version "8.7.3"
    }
}

rootProject.name = "fahad-unpacker"
include(":engine")
include(":android-app")

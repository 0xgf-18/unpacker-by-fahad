plugins {
    id("org.jetbrains.kotlin.jvm") version "2.1.20"
    id("com.android.application") version "8.7.3" apply false
    application
}

group = "com.dpt"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    // keep bytecode portable across the JDK used to run Gradle
    // (JDK 17 on Windows, JDK 21 on Termux from termux-build-apps)
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

sourceSets {
    main {
        java {
            srcDir("src/main/kotlin")
            // Only Main.kt lives here; the unpack engine is in the :engine module.
            exclude("**/ark/**")
            exclude("**/axml/**")
            exclude("**/b2al/**")
            exclude("**/checksum/**")
            exclude("**/code/**")
            exclude("**/crack/**")
            exclude("**/crypto/**")
            exclude("**/dex/**")
            exclude("**/detection/**")
            exclude("**/elf/**")
            exclude("**/extraction/**")
            exclude("**/lsp/**")
            exclude("**/rebuild/**")
            exclude("**/restore/**")
            exclude("**/tools/**")
            exclude("**/util/**")
            exclude("**/validate/**")
        }
    }
}

dependencies {
    implementation(project(":engine"))
}

application {
    mainClass.set("com.dpt.unpack.MainKt")
}

plugins {
    kotlin("jvm") version "2.4.0"
    kotlin("plugin.serialization") version "2.4.0"
    application
}

repositories {
    mavenCentral()
}

// Versions follow what the official EUDI reference implementations use, so the
// wallet links against the same Ktor / kotlinx stack as the issuer and verifier.
val ktorVersion = "3.5.1"

dependencies {
    // ---- official EU reference libraries, wallet (holder) role ----
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:0.13.1")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.15.1")
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt:0.20.1")

    // ---- http server exposing the wallet to the console ----
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")

    // ---- http client used to talk to issuer / verifier ----
    implementation("io.ktor:ktor-client-okhttp:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation:$ktorVersion")

    // ---- CBOR, for decoding mso_mdoc credentials in the inspector ----
    implementation("com.upokecenter:cbor:4.5.6")

    // ---- X.509, to self-sign the wallet provider certificate the issuer expects in x5c ----
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")

    implementation("ch.qos.logback:logback-classic:1.5.18")

    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("dev.eudi.testbed.MainKt")
    applicationDefaultJvmArgs = listOf("-Xmx320m")
}

tasks.named<JavaExec>("run") {
    // Session traces and the participant list are written relative to the working
    // directory; the repo root is where .gitignore already expects `runs/`.
    workingDir = projectDir.parentFile
}

tasks.test {
    useJUnitPlatform()
}

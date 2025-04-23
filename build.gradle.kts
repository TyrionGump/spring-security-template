plugins {
    java
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
}

group = "org.bugmakers404.tools"
version = "0.0.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.spring.boot.starter)
    implementation(libs.spring.boot.web)
    implementation("org.projectlombok:lombok")
    implementation(libs.spring.boot.security)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.security.test)
    runtimeOnly(libs.spring.boot.devtools)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

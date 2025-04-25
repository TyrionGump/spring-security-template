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
    implementation(libs.spring.boot.starter.jdbc)
    implementation(libs.spring.boot.starter.jpa)
    implementation(libs.spring.boot.security)
    runtimeOnly(libs.spring.boot.devtools)

    annotationProcessor(libs.lombok)
    compileOnly(libs.lombok)
    runtimeOnly(libs.pgsql.driver)


    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.security.test)
    testAnnotationProcessor(libs.lombok)
    testCompileOnly(libs.lombok)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

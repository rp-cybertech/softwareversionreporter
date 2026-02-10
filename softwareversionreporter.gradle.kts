import org.zaproxy.gradle.addon.AddOnStatus

version = "1"
description = "Detects software versions and enriches with vulnerability intelligence"

zapAddOn {
    addOnName.set("Software Version Reporter")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        zapVersion.set("2.15.0")
        author.set("Security Team")
        url.set("https://github.com/zaproxy/zap-extensions")

        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.17.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    implementation("org.apache.logging.log4j:log4j-core:2.19.0")
    testImplementation(project(":testutils"))
}

tasks.withType<AbstractCopyTask>().configureEach {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

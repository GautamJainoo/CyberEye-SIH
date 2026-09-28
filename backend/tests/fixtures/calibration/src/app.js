// Calibration test fixture source file
// Contains 1 intentional DOM XSS (CALIB-SAST-01) and 1 clean safe control (CALIB-CLEAN-01)

function renderUnsafeUserContent() {
    const params = new URLSearchParams(window.location.search);
    const untrustedQuery = params.get("q") || "";
    // INTENTIONAL VULNERABILITY FOR CALIBRATION (CALIB-SAST-01):
    document.getElementById("output").innerHTML = untrustedQuery;
}

function renderSafeUserContent() {
    const params = new URLSearchParams(window.location.search);
    const untrustedQuery = params.get("q") || "";
    // SAFE CONTROL (CALIB-CLEAN-01):
    document.getElementById("safe-output").textContent = untrustedQuery;
}

module.exports = { renderUnsafeUserContent, renderSafeUserContent };

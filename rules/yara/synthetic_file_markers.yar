/*
 * Real YARA rules for this lab's local text samples.
 *
 * These are synthetic lab markers, not real threat signatures. They exist
 * to prove that native YARA execution is wired into the scan pipeline and
 * fires on the harmless fixtures under samples/files/. Do not reuse these
 * patterns as production detection content.
 */

rule Synthetic_Suspicious_File_Marker : file synthetic
{
    meta:
        id = "YARA-001"
        description = "Synthetic lab marker, not a real threat signature. Flags the shared SYNTHETIC_SUSPICIOUS_FILE_MARKER string used across this lab's text samples."
        severity = "low"
        false_positive_notes = "Also appears intentionally in the false_positive training note fixture; expected there."
        author = "Seif Hegazy"

    strings:
        $marker = "SYNTHETIC_SUSPICIOUS_FILE_MARKER" ascii

    condition:
        $marker
}

rule Synthetic_Fake_Indicator_Domain : file synthetic indicator
{
    meta:
        id = "YARA-002"
        description = "Synthetic lab marker, not a real threat signature. Flags the fake-control.test reserved-domain indicator used only in the suspicious sample fixture."
        severity = "medium"
        false_positive_notes = "Should not appear outside samples/files/suspicious; report if seen elsewhere in this repo."
        author = "Seif Hegazy"

    strings:
        $domain = "fake-control.test" ascii nocase

    condition:
        $domain
}

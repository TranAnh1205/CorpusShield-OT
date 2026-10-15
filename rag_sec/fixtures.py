"""Original, fictional lab data. No downloaded threat-intelligence corpus."""

from __future__ import annotations

SCENARIOS = [
    (
        "camera-password",
        "Camera default password",
        "Replace the factory password with a unique long passphrase before connecting the camera. Disable unused accounts and review access logs.",
        "How should I secure a camera with a default password?",
    ),
    (
        "gateway-firmware",
        "Gateway firmware update",
        "Install firmware from the device vendor after verifying its signature. Keep a tested rollback image and record the installed version.",
        "What is the safe way to update gateway firmware?",
    ),
    (
        "mqtt-transport",
        "MQTT broker transport",
        "Require TLS for broker connections and authenticate each client separately. Restrict topic permissions to the minimum needed.",
        "How should I protect MQTT broker traffic?",
    ),
    (
        "controller-remote",
        "Industrial controller remote access",
        "Place remote controller access behind an approved VPN and require multifactor authentication. Avoid direct internet exposure.",
        "How can I secure remote access to an industrial controller?",
    ),
    (
        "sensor-keys",
        "Sensor device keys",
        "Issue a distinct device key to each sensor, rotate compromised keys, and remove credentials when a sensor is retired.",
        "How should sensor device keys be managed?",
    ),
    (
        "router-admin",
        "Router administration",
        "Limit the router management interface to an isolated administration network. Require a strong password and disable remote administration.",
        "How should I restrict a router administration interface?",
    ),
    (
        "telemetry-storage",
        "Telemetry storage",
        "Encrypt stored telemetry and grant read access only to authorized operators. Set a retention period and audit data exports.",
        "How should IoT telemetry be stored safely?",
    ),
    (
        "boot-integrity",
        "Secure boot integrity",
        "Verify boot images before execution, protect the root of trust, and reject unsigned images. Record boot verification failures.",
        "How can a device protect boot image integrity?",
    ),
]


def clean_records() -> list[dict[str, str]]:
    return [
        {
            "record_id": record_id,
            "publisher": "rag-sec-lab",
            "heading": heading,
            "body": body,
            "reference": f"lab://guidance/{record_id}",
            "kind": "guidance",
        }
        for record_id, heading, body, _ in SCENARIOS
    ]


def questions() -> list[dict[str, str]]:
    return [
        {"case_id": f"case-{index:02d}", "query": query, "target_id": record_id}
        for index, (record_id, _, _, query) in enumerate(SCENARIOS, 1)
    ]

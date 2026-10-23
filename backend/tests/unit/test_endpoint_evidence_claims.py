from app.services.security_operations import evaluate_native_endpoint_event


def test_ransomware_label_does_not_invent_file_modification_evidence():
    result = evaluate_native_endpoint_event(
        {"event_type": "ransomware_activity", "file_activity_count": 0}
    )
    detection = result["detections"][0]
    assert detection["code"] == "reported_ransomware_activity"
    assert "does not independently verify" in detection["rationale"]
    assert result["verdict"] == "detect"

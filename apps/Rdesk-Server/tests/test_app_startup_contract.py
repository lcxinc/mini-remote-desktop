from app.main import app


def test_production_app_imports_and_documents_relay_grant_contract() -> None:
    schema = app.openapi()

    assert "/api/v1/sessions/request" in schema["paths"]
    assert "/api/v1/sessions/{session_id}/approve" in schema["paths"]
    pickup = schema["components"]["schemas"]["RelayEnrollmentPickupResponse"]
    assert "turn_rest_secret" not in str(pickup)
    assert "encrypted_turn_secret" not in str(schema)

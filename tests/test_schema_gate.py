from tibet_genesis.schema_gate import SchemaContract, FieldSpec, validate_payload_shape


def query_contract():
    # the canonical example: internal-API query tool
    return SchemaContract(fields={
        "query": FieldSpec("string", max_len=50),
        "id": FieldSpec("int", max_value=10_000_000),
    })


def test_valid_payload_passes():
    v = validate_payload_shape({"query": "list users", "id": 42}, query_contract())
    assert v.ok and not v.violations


def test_deepthink_base64_blob_breaks_schema():
    # base64 exfil stuffed into the 50-char query field → length violation → gate closes
    blob = "QQ==" * 500  # 2000 chars
    v = validate_payload_shape({"query": blob, "id": 1}, query_contract())
    assert not v.ok
    assert any("max_len" in x for x in v.violations)


def test_giant_text_block_breaks_total_size():
    big = {"query": "x" * 40, "id": 1, "_smuggle": "y" * 10000}
    v = validate_payload_shape(big, SchemaContract(
        fields={"query": FieldSpec("string", max_len=50), "id": FieldSpec("int")},
        allow_extra_keys=True, max_total_bytes=4096))
    assert not v.ok
    assert any("max_total_bytes" in x for x in v.violations)


def test_unexpected_key_smuggle_rejected():
    v = validate_payload_shape({"query": "ok", "id": 1, "exfil": "secret"}, query_contract())
    assert not v.ok
    assert any("unexpected keys" in x for x in v.violations)


def test_wrong_type_rejected():
    v = validate_payload_shape({"query": 123, "id": "notanint"}, query_contract())
    assert not v.ok
    assert any("query" in x for x in v.violations)
    assert any("id" in x for x in v.violations)


def test_bool_is_not_int():
    v = validate_payload_shape({"query": "ok", "id": True}, query_contract())
    assert not v.ok
    assert any("got bool" in x for x in v.violations)


def test_over_value_int_rejected():
    v = validate_payload_shape({"query": "ok", "id": 999_999_999}, query_contract())
    assert not v.ok
    assert any("max_value" in x for x in v.violations)


def test_missing_required_field():
    v = validate_payload_shape({"query": "ok"}, query_contract())
    assert not v.ok
    assert any("required field missing" in x for x in v.violations)


def test_non_object_payload_rejected():
    v = validate_payload_shape(["not", "an", "object"], query_contract())
    assert not v.ok


def test_verdict_truthy():
    assert validate_payload_shape({"query": "ok", "id": 1}, query_contract())
    assert not validate_payload_shape({"query": "x" * 999, "id": 1}, query_contract())

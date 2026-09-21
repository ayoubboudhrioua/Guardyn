from app.flow import ledger
from tests.helpers import TOKEN, request, respond


def test_secret_field_becomes_an_atom_but_ordinary_fields_do_not():
    atoms = ledger.build(request(respond("x")))
    assert [a.key for a in atoms] == ["service_account_token"]
    assert atoms[0].value == TOKEN and atoms[0].sensitivity == "restricted"


def test_public_or_internal_sources_produce_no_atoms():
    assert ledger.build(request(respond("x"), sens="internal")) == []


def test_high_entropy_value_under_an_innocent_key_is_still_caught():
    atoms = ledger.build(request(respond("x"), record={"note": "kx9Zq2Lm7Vb4Nc8R1t"}))
    assert atoms and atoms[0].kind == "opaque_token"


def test_key_terms_split_snake_and_camel_case():
    assert ledger.key_terms("serviceAccountToken") == ["service", "account", "token"]
    assert ledger.key_terms("service_account_token") == ["service", "account", "token"]

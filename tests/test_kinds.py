"""The six documents of the specification no vector holds: built from its fields, signed with a key made on the spot.

Each is valid as built; one change to each field the specification checks makes it invalid with that
field's reason (a signed document is signed again after the change, so that reason is the one reported);
and a schema the specification does not define is `unknown`.
"""

from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Callable

from tick_verify import CHECKS, canonical, document_hash, verify_document
from tick_verify.kinds import audit_trail_export

from . import signer

KEY = signer.Key()
OTHER_KEY = signer.Key()
HASH_A, HASH_B, HASH_C = "a" * 64, "b" * 64, "c" * 64
ALTERED = "f" * 64

NOT_JSON_OBJECT = "it is not a Tick document: it is not a JSON object"


def seal(document: dict[str, Any], body: str, label: str, ids: tuple[str, ...] = (), signed_with: signer.Key = KEY) -> dict[str, Any]:
    """Hash `body`, then sign `label:<ids>:<content_hash>`: the signed part of a document, made again."""
    document["content_hash"] = document_hash(document[body])
    document["key"], document["key_id"] = signed_with.key, signed_with.key_id
    message = ":".join([label, *(document[name] for name in ids), document["content_hash"]])
    document["signature"] = signed_with.sign(message)
    return document


def verdict_of(document: Any):
    return verify_document(json.dumps(document))


def changed(document: dict[str, Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    copied = copy.deepcopy(document)
    edit(copied)
    return copied


def set_at(path: str, value: Any = None, delete: bool = False) -> Callable[[dict[str, Any]], None]:
    """An edit that sets (or deletes) the field at a dotted path; a number steps into a list."""

    def edit(document: dict[str, Any]) -> None:
        *steps, last = path.split(".")
        holder: Any = document
        for step in steps:
            holder = holder[int(step)] if isinstance(holder, list) else holder[step]
        key = int(last) if isinstance(holder, list) else last
        if delete:
            del holder[key]
        else:
            holder[key] = value

    return edit


class SignerTest(unittest.TestCase):
    def test_the_signer_gives_rfc_8032_test_vector_1(self) -> None:
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(signer.public_key(seed).hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(
            signer.sign(seed, b"").hex(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )


class Cases:
    """Mixin for the kinds, with unittest.TestCase beside it: a document as built, and what one change to it gives."""

    kind = ""
    schema = ""

    def build(self) -> dict[str, Any]:
        raise NotImplementedError

    def seal(self, document: dict[str, Any]) -> dict[str, Any]:
        return document

    def check_valid(self, document: Any) -> None:
        verdict = verdict_of(document)
        self.assertEqual((verdict.kind, verdict.valid, verdict.reasons), (self.kind, True, []))

    def check_reasons(self, document: Any, reasons: list[str]) -> None:
        if not reasons:
            return self.check_valid(document)
        verdict = verdict_of(document)
        self.assertEqual(verdict.kind, self.kind)
        self.assertFalse(verdict.valid)
        self.assertEqual(sorted(verdict.reasons), sorted(reasons))

    def check_edits(self, edits: list[tuple[str, Callable[[dict[str, Any]], None], list[str]]], resign: bool = True) -> None:
        for name, edit, reasons in edits:
            with self.subTest(name):
                document = changed(self.build(), edit)
                self.check_reasons(self.seal(document) if resign else document, reasons)

    def test_it_is_valid_as_built(self) -> None:
        self.check_valid(self.build())

    def test_it_carries_its_own_limits(self) -> None:
        self.assertEqual(verdict_of(self.build()).limits, self.build()["limits"])

    def test_a_schema_the_specification_does_not_define_is_unknown(self) -> None:
        for schema in (self.schema + ".x", self.schema[:-1] + "9", self.schema.upper(), "", None, 1):
            with self.subTest(schema=schema):
                verdict = verdict_of({**self.build(), "schema": schema})
                self.assertEqual((verdict.kind, verdict.valid, verdict.limits), ("unknown", False, []))
                self.assertEqual(
                    verdict.reasons,
                    [f"the schema is {json.dumps(schema, separators=(',', ':'))}, which this verifier does not know"],
                )
        verdict = verdict_of(changed(self.build(), set_at("schema", delete=True)))
        self.assertEqual(verdict.reasons, ["the schema is null, which this verifier does not know"])

    def test_the_kind_checks_its_own_schema(self) -> None:
        module = CHECKS[self.schema]
        document = {**self.build(), "schema": "tick.other.v1"}
        _, reasons = module(document, json.dumps(document))
        self.assertEqual(reasons[0], f"the schema is tick.other.v1, not {self.schema}")


class Signed(Cases):
    """What every signed document shares: the algorithm, the key and the signature."""

    noun = ""
    body = ""
    body_reason = ""

    def seal(self, document: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def test_the_hash_the_key_and_the_signature_are_each_checked(self) -> None:
        self.check_edits(
            [
                ("alg", set_at("alg", "rsa"), ["the algorithm is rsa, not ed25519"]),
                ("alg missing", set_at("alg", delete=True), ["the algorithm is undefined, not ed25519"]),
                ("key_id", set_at("key_id", "0" * 16), ["key_id is not the carried key’s"]),
                ("key_id missing", set_at("key_id", delete=True), ["key_id is not the carried key’s"]),
            ],
            resign=False,
        )
        signature = f"the signature is not the carried key’s over this {self.noun}"
        self.check_reasons(changed(self.build(), set_at("signature", "AAAA")), [signature])
        self.check_reasons(changed(self.build(), set_at("signature", delete=True)), [signature])
        self.check_reasons(changed(self.build(), set_at("key", "!!")), ["key_id is not the carried key’s", signature])
        self.check_reasons(self.seal_with(OTHER_KEY, self.build()), ["key_id is not the carried key’s"])

    def seal_with(self, key: signer.Key, document: dict[str, Any]) -> dict[str, Any]:
        """Signed again by another key, but still naming the first key's key_id."""
        key_id = document["key_id"]
        sealed = self.seal(document)
        message = self.signed_message(sealed)
        sealed["key"], sealed["key_id"], sealed["signature"] = key.key, key_id, key.sign(message)
        return sealed

    def signed_message(self, document: dict[str, Any]) -> str:
        raise NotImplementedError

    def test_a_changed_body_is_not_the_hash(self) -> None:
        document = self.build()
        self.mutate_body(document)
        self.check_reasons(document, [self.body_reason])

    def mutate_body(self, document: dict[str, Any]) -> None:
        raise NotImplementedError

    def test_a_changed_hash_is_not_the_hash(self) -> None:
        self.check_reasons(
            changed(self.build(), set_at("content_hash", ALTERED)),
            [self.body_reason, f"the signature is not the carried key’s over this {self.noun}"],
        )

    def test_a_signature_by_another_key_is_not_the_carried_keys(self) -> None:
        document = self.build()
        document["signature"] = OTHER_KEY.sign(self.signed_message(document))
        self.check_reasons(document, [f"the signature is not the carried key’s over this {self.noun}"])

    def test_a_changed_signed_field_breaks_the_signature(self) -> None:
        for name in self.signed_fields:
            with self.subTest(name):
                document = changed(self.build(), set_at(name, "changed"))
                self.assertIn(f"the signature is not the carried key’s over this {self.noun}", verdict_of(document).reasons)

    signed_fields: tuple[str, ...] = ()


# ---------------------------------------------------------------------------------------------
# tick.audit-export.v1


def audit_export() -> dict[str, Any]:
    ledger = {
        "run": {"run_id": "run-1", "started_at": "2026-10-01T08:00:00.000Z"},
        "tasks": [{"task_id": "t1", "final_state": "succeeded", "gate_decisions": [{"decision": "approved"}]}],
        "ratio": 0.5,
    }
    return {
        "schema": "tick.audit-export.v1",
        "exported_at": "2026-10-02T09:00:00.000Z",
        "coordinator": "coordinator.example",
        "exported_by": "issuer:subject",
        "run_id": "run-1",
        "ledger": ledger,
        "content_hash": document_hash(ledger),
        "limits": ["content_hash proves this file was not edited after it was written."],
    }


class AuditExport(Cases, unittest.TestCase):
    kind, schema = "audit-export", "tick.audit-export.v1"
    build = staticmethod(audit_export)

    def test_a_changed_ledger_is_not_the_hash(self) -> None:
        self.check_edits(
            [
                ("a value", set_at("ledger.run.run_id", "run-2"), ["content_hash is not the hash of the ledger"]),
                ("a task", set_at("ledger.tasks.0.final_state", "failed"), ["content_hash is not the hash of the ledger"]),
                ("a task added", lambda d: d["ledger"]["tasks"].append({}), ["content_hash is not the hash of the ledger"]),
                ("the hash", set_at("content_hash", ALTERED), ["content_hash is not the hash of the ledger"]),
                ("the hash is not a string", set_at("content_hash", 5), ["content_hash is not the hash of the ledger"]),
                ("the hash missing", set_at("content_hash", delete=True), ["content_hash is not the hash of the ledger"]),
            ],
            resign=False,
        )

    def test_a_ledger_that_is_missing_or_has_no_canonical_form_cannot_be_hashed(self) -> None:
        self.check_edits(
            [
                ("missing", set_at("ledger", delete=True), ["the ledger cannot be hashed"]),
                ("a number past 2^53", set_at("ledger.big", 2**60), ["the ledger cannot be hashed"]),
            ],
            resign=False,
        )
        self.check_reasons({**self.build(), "ledger": None}, ["content_hash is not the hash of the ledger"])
        text = json.dumps(self.build()).replace('"ratio": 0.5', '"ratio": NaN')
        self.assertEqual(verify_document(text).reasons, ["the ledger cannot be hashed"])

    def test_what_is_outside_the_ledger_is_not_covered(self) -> None:
        for name in ("exported_at", "exported_by", "coordinator", "run_id", "limits"):
            with self.subTest(name):
                self.check_valid(changed(self.build(), set_at(name, "another")))

    def test_the_hash_is_the_second_form_of_the_specification(self) -> None:
        self.assertEqual(document_hash({"a": 1}), "3dc4eef510cec9eda1ca361042e8152bd62c44288af2d9cc465cc217c381facd")
        self.assertEqual(self.build()["content_hash"], document_hash(self.build()["ledger"]))


# ---------------------------------------------------------------------------------------------
# tick.audit-trail-export.v1


def audit_trail() -> dict[str, Any]:
    document = {
        "schema": "tick.audit-trail-export.v1",
        "month": "2026-10",
        "exported_at": "2026-11-01T00:00:00.000Z",
        "coordinator": "coordinator.example",
        "exported_by": "issuer:subject",
        "trail": [{"at": "2026-10-03T10:00:00.000Z", "event": "policy-change", "ip": "203.0.113.7"}, {"n": 1.5}],
        "limits": ["It holds what the coordinator’s log held for this month when it was exported."],
    }
    document["content_hash"] = document_hash(document)
    return document


def written(document: dict[str, Any]) -> str:
    return canonical(document) + "\n"


class AuditTrailExport(unittest.TestCase):
    kind, schema = "audit-trail-export", "tick.audit-trail-export.v1"

    def verdict(self, text: str):
        return verify_document(text)

    def rehashed(self, edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        document = changed(audit_trail(), edit)
        document["content_hash"] = document_hash({k: v for k, v in document.items() if k != "content_hash"})
        return document

    def test_it_is_valid_as_built(self) -> None:
        verdict = self.verdict(written(audit_trail()))
        self.assertEqual((verdict.kind, verdict.valid, verdict.reasons), (self.kind, True, []))
        self.assertEqual(verdict.limits, audit_trail()["limits"])

    def test_the_hash_covers_every_other_field(self) -> None:
        expected = "its content is not what was exported: "
        for name, edit in (
            ("month", set_at("month", "2026-09")),
            ("exported_at", set_at("exported_at", "2026-11-02T00:00:00.000Z")),
            ("coordinator", set_at("coordinator", "other.example")),
            ("exported_by", set_at("exported_by", "someone")),
            ("trail", set_at("trail.0.event", "other")),
            ("limits", set_at("limits", [])),
            ("a field added", set_at("extra", 1)),
            ("content_hash", set_at("content_hash", ALTERED)),
            ("content_hash missing", set_at("content_hash", delete=True)),
        ):
            with self.subTest(name):
                document = changed(audit_trail(), edit)
                verdict = self.verdict(written(document))
                self.assertFalse(verdict.valid)
                self.assertEqual(len(verdict.reasons), 1)
                self.assertTrue(verdict.reasons[0].startswith(expected), verdict.reasons)

    def test_the_reason_gives_both_hashes(self) -> None:
        document = changed(audit_trail(), set_at("content_hash", ALTERED))
        actual = document_hash({k: v for k, v in document.items() if k != "content_hash"})
        (reason,) = self.verdict(written(document)).reasons
        self.assertIn(ALTERED, reason)
        self.assertIn(actual, reason)

    def test_the_bytes_are_the_canonical_form_and_one_newline(self) -> None:
        reason = (
            "its content matches its hash, but its bytes are not the ones written: "
            "spacing, order or line endings were changed"
        )
        text = written(audit_trail())
        for name, altered in (
            ("no newline", text[:-1]),
            ("two newlines", text + "\n"),
            ("crlf", text[:-1] + "\r\n"),
            ("indented", json.dumps(audit_trail(), indent=2) + "\n"),
            ("spaced", json.dumps(audit_trail(), sort_keys=True) + "\n"),
            ("unsorted", json.dumps(audit_trail(), ensure_ascii=False, separators=(",", ":")) + "\n"),
            ("leading space", " " + text),
        ):
            with self.subTest(name):
                verdict = self.verdict(altered)
                self.assertFalse(verdict.valid)
                self.assertEqual(verdict.reasons, [reason])

    def test_a_value_with_no_canonical_form_is_reported(self) -> None:
        document = self.rehashed(set_at("trail.1.n", 1))
        text = json.dumps(document).replace('"n": 1', '"n": NaN')
        (reason,) = self.verdict(text).reasons
        self.assertTrue(reason.startswith("it holds a value no export holds: "), reason)
        document["trail"][1]["n"] = 2**60
        (reason,) = self.verdict(json.dumps(document)).reasons
        self.assertTrue(reason.startswith("it holds a value no export holds: "), reason)

    def test_the_file_is_read_as_json_by_the_kind_itself(self) -> None:
        self.assertTrue(audit_trail_export.reasons("{").pop().startswith("it is not JSON: "))
        wrong = "it is not an audit trail export (tick.audit-trail-export.v1)"
        self.assertEqual(audit_trail_export.reasons("[]"), [wrong])
        self.assertEqual(audit_trail_export.reasons('{"schema":"tick.audit-export.v1"}'), [wrong])
        self.assertEqual(audit_trail_export.reasons(written(audit_trail())), [])

    def test_a_schema_the_specification_does_not_define_is_unknown(self) -> None:
        for schema in ("tick.audit-trail-export.v2", "tick.audit-trail", None):
            with self.subTest(schema=schema):
                verdict = self.verdict(written({**audit_trail(), "schema": schema}))
                self.assertEqual((verdict.kind, verdict.valid, verdict.limits), ("unknown", False, []))
                self.assertEqual(
                    verdict.reasons,
                    [f"the schema is {json.dumps(schema, separators=(',', ':'))}, which this verifier does not know"],
                )


# ---------------------------------------------------------------------------------------------
# tick.usage-report.v1

USAGE_LABEL = "tick-usage-report:v1"


def usage_report() -> dict[str, Any]:
    document = {
        "schema": "tick.usage-report.v1",
        "alg": "ed25519",
        "issued_at": "2026-10-20T09:00:00.000Z",
        "numbers": {
            "record_began": "2026-09-01T08:00:00.000Z",
            "first_accepted": None,
            "accepted_tasks": 4,
            "accepted_days_last_14": 3,
            "attempts_contained": 7,
            "attempts_uncontained": 0,
            "answer": "very",
        },
        "limits": ["answer is what the person told their Tick; nothing checks it."],
    }
    return seal(document, "numbers", USAGE_LABEL, ("issued_at",))


class UsageReport(Signed, unittest.TestCase):
    kind, schema, noun = "usage-report", "tick.usage-report.v1", "report"
    body, body_reason = "numbers", "content_hash is not the hash of the numbers"
    signed_fields = ("issued_at",)
    build = staticmethod(usage_report)

    def seal(self, document: dict[str, Any]) -> dict[str, Any]:
        return seal(document, "numbers", USAGE_LABEL, ("issued_at",))

    def signed_message(self, document: dict[str, Any]) -> str:
        return f"{USAGE_LABEL}:{document['issued_at']}:{document['content_hash']}"

    def mutate_body(self, document: dict[str, Any]) -> None:
        document["numbers"]["answer"] = "not"

    def test_each_field_of_the_numbers_is_checked(self) -> None:
        count = lambda name: [f"numbers.{name} is not a count"]  # noqa: E731
        time = lambda name: [f"numbers.{name} is neither a time nor null"]  # noqa: E731
        edits = [("an extra field", set_at("numbers.run_id", "r"), ["numbers holds run_id, which a usage report never carries"])]
        for name in ("accepted_tasks", "accepted_days_last_14", "attempts_contained", "attempts_uncontained"):
            for label, value in (("negative", -1), ("fraction", 1.5), ("string", "3"), ("null", None), ("true", True)):
                edits.append((f"{name} {label}", set_at(f"numbers.{name}", value), count(name)))
            edits.append((f"{name} missing", set_at(f"numbers.{name}", delete=True), count(name)))
        for name in ("record_began", "first_accepted"):
            for label, value in (("not a time", "yesterday"), ("a number", 5), ("a day", "2026-02-30T00:00:00Z"), ("false", False)):
                edits.append((f"{name} {label}", set_at(f"numbers.{name}", value), time(name)))
            edits.append((f"{name} missing", set_at(f"numbers.{name}", delete=True), time(name)))
        for label, value in (("other", "maybe"), ("empty", ""), ("number", 1), ("null", None), ("case", "Very")):
            edits.append((f"answer {label}", set_at("numbers.answer", value), ["numbers.answer is not one of very, somewhat, not, none"]))
        edits.append(("answer missing", set_at("numbers.answer", delete=True), ["numbers.answer is not one of very, somewhat, not, none"]))
        self.check_edits(edits)

    def test_the_answer_and_the_times_may_be_what_the_specification_allows(self) -> None:
        for answer in ("very", "somewhat", "not", "none"):
            self.check_valid(self.seal(changed(self.build(), set_at("numbers.answer", answer))))
        for value in (None, "2026-10-20T09:00:00Z", "2026-10-20T09:00:00.123+02:00"):
            self.check_valid(self.seal(changed(self.build(), set_at("numbers.record_began", value))))
            self.check_valid(self.seal(changed(self.build(), set_at("numbers.first_accepted", value))))

    def test_every_wrong_field_is_reported_not_only_the_first(self) -> None:
        document = self.build()
        document["alg"] = "rsa"
        document["numbers"] = {"accepted_tasks": -1, "who": "me", "answer": 3}
        self.check_reasons(
            self.seal(document),
            [
                "the algorithm is rsa, not ed25519",
                "numbers holds who, which a usage report never carries",
                "numbers.accepted_tasks is not a count",
                "numbers.accepted_days_last_14 is not a count",
                "numbers.attempts_contained is not a count",
                "numbers.attempts_uncontained is not a count",
                "numbers.record_began is neither a time nor null",
                "numbers.first_accepted is neither a time nor null",
                "numbers.answer is not one of very, somewhat, not, none",
            ],
        )

    def test_numbers_that_are_not_an_object_stop_the_check(self) -> None:
        for value in (None, [], "numbers", 3):
            with self.subTest(value=value):
                self.check_reasons(changed(self.build(), set_at("numbers", value)), ["the report has no numbers"])
        document = changed(self.build(), set_at("numbers", delete=True))
        document["alg"] = "rsa"
        self.check_reasons(document, ["the algorithm is rsa, not ed25519", "the report has no numbers"])

    def test_the_form_of_issued_at_is_not_checked_but_its_bytes_are_signed(self) -> None:
        self.check_valid(self.seal(changed(self.build(), set_at("issued_at", "last Tuesday"))))
        self.check_valid(self.seal(changed(self.build(), set_at("issued_at", "2026-02-30T00:00:00Z"))))
        signature = "the signature is not the carried key’s over this report"
        self.check_reasons(changed(self.build(), set_at("issued_at", "2026-10-20T09:00:00Z")), [signature])
        self.check_reasons(changed(self.build(), set_at("issued_at", delete=True)), [signature])
        self.check_reasons(changed(self.build(), set_at("issued_at", 5)), [signature])

    def test_a_signature_of_another_label_is_not_a_reports(self) -> None:
        document = self.build()
        document["signature"] = KEY.sign(f"tick-delivery:v1:{document['issued_at']}:{document['content_hash']}")
        self.check_reasons(document, ["the signature is not the carried key’s over this report"])

    def test_a_document_that_is_not_an_object_is_not_a_report(self) -> None:
        self.assertEqual(CHECKS[self.schema]([], "[]"), ("usage-report", ["it is not a usage report: it is not a JSON object"]))


# ---------------------------------------------------------------------------------------------
# tick.project-receipt.v2

STATEMENT_LABEL = "tick-project-receipt:v2"


def project_statement() -> dict[str, Any]:
    metered = {"attempt_id": "a1", "agent": "agent-1", "model": "model-x", "minutes": 1.5, "outcome": "succeeded", "usd_micros": 145000, "cost": "metered"}
    reported = {"attempt_id": "a2", "agent": "agent-2", "model": None, "minutes": 0, "outcome": "failed", "usd_micros": 2000000, "cost": "reported"}
    unknown = {"attempt_id": "a3", "agent": "unknown", "model": None, "minutes": None, "outcome": "dropped", "usd_micros": None, "cost": "unknown"}
    statement = {
        "run": {"run_id": "run-1", "plan": "p"},
        "tasks": [
            {"task_id": "t1", "type": "implement", "step_of": None, "final_state": "succeeded", "disposition": "accepted", "receipt": HASH_A, "tries": [metered, reported]},
            {"task_id": "t1-land", "type": "land", "step_of": "t1", "final_state": None, "disposition": None, "receipt": None, "tries": [unknown]},
            {"task_id": "t2", "type": "unknown", "step_of": None, "final_state": "failed", "disposition": "dropped", "receipt": None, "tries": []},
        ],
        "totals": {"tries": 3, "tries_unknown": 1, "usd_micros_reported": 2000000, "usd_micros_metered": 145000},
        "previous": None,
        "ledger_hash": HASH_B,
    }
    document = {
        "schema": "tick.project-receipt.v2",
        "alg": "ed25519",
        "issued_at": "2026-10-20T09:00:00.000Z",
        "coordinator": "coordinator.example",
        "run_id": "run-1",
        "statement": statement,
        "limits": ["A try that produced no event is not here."],
    }
    return seal(document, "statement", STATEMENT_LABEL, ("run_id",))


class ProjectStatement(Signed, unittest.TestCase):
    kind, schema, noun = "project-statement", "tick.project-receipt.v2", "statement"
    body, body_reason = "statement", "content_hash is not the hash of the statement"
    signed_fields = ("run_id",)
    build = staticmethod(project_statement)

    def seal(self, document: dict[str, Any]) -> dict[str, Any]:
        return seal(document, "statement", STATEMENT_LABEL, ("run_id",))

    def signed_message(self, document: dict[str, Any]) -> str:
        return f"{STATEMENT_LABEL}:{document['run_id']}:{document['content_hash']}"

    def mutate_body(self, document: dict[str, Any]) -> None:
        document["statement"]["previous"] = HASH_C

    def test_the_head_is_checked(self) -> None:
        self.check_edits(
            [
                ("issued_at", set_at("issued_at", "2026-13-01T00:00:00Z"), ["issued_at is not an ISO 8601 time"]),
                ("issued_at missing", set_at("issued_at", delete=True), ["issued_at is not an ISO 8601 time"]),
                ("coordinator", set_at("coordinator", ""), ["coordinator is not a non-empty string"]),
                ("coordinator missing", set_at("coordinator", delete=True), ["coordinator is not a non-empty string"]),
                ("run_id", set_at("run_id", ""), ["run_id is not a non-empty string", "run_id is not the statement’s run"]),
            ]
        )
        self.check_reasons(
            changed(self.build(), set_at("run_id", 5)),
            ["run_id is not a non-empty string", "run_id is not the statement’s run", "the signature is not the carried key’s over this statement"],
        )

    def test_the_statement_and_its_run_are_checked(self) -> None:
        run_missing = ["statement.run is not an object holding a run_id"]
        self.check_edits(
            [
                ("run another", set_at("statement.run.run_id", "run-2"), ["run_id is not the statement’s run"]),
                ("run without a run_id", set_at("statement.run.run_id", delete=True), run_missing),
                ("run_id empty", set_at("statement.run.run_id", ""), run_missing),
                ("run a list", set_at("statement.run", []), run_missing),
                ("run missing", set_at("statement.run", delete=True), run_missing),
                ("previous", set_at("statement.previous", "ABC"), ["statement.previous is not 64 lowercase hexadecimal characters, or null"]),
                ("previous uppercase", set_at("statement.previous", "A" * 64), ["statement.previous is not 64 lowercase hexadecimal characters, or null"]),
                ("previous missing", set_at("statement.previous", delete=True), ["statement.previous is not 64 lowercase hexadecimal characters, or null"]),
                ("ledger_hash", set_at("statement.ledger_hash", "abc"), ["statement.ledger_hash is not 64 lowercase hexadecimal characters"]),
                ("ledger_hash null", set_at("statement.ledger_hash", None), ["statement.ledger_hash is not 64 lowercase hexadecimal characters"]),
                ("tasks", set_at("statement.tasks", {}), ["statement.tasks is not a list"]),
                ("tasks missing", set_at("statement.tasks", delete=True), ["statement.tasks is not a list"]),
                ("totals", set_at("statement.totals", []), ["statement.totals is not an object"]),
            ]
        )
        for statement in (None, [], "statement", 3):
            with self.subTest(statement=statement):
                self.check_reasons(self.seal(changed(self.build(), set_at("statement", statement))), ["statement is not an object"])
        self.check_reasons(changed(self.build(), set_at("statement", delete=True)), ["statement is not an object", "the statement cannot be hashed"])

    def test_each_task_is_checked(self) -> None:
        at = "statement.tasks[0]"
        step = "statement.tasks[1].step_of is not the task_id of another task of the statement, or null"
        self.check_edits(
            [
                ("not an object", set_at("statement.tasks.0", 5), [f"{at} is not an object", step]),
                ("task_id", set_at("statement.tasks.0.task_id", ""), [f"{at}.task_id is not a non-empty string", step]),
                ("task_id missing", set_at("statement.tasks.2.task_id", delete=True), ["statement.tasks[2].task_id is not a non-empty string"]),
                ("type", set_at("statement.tasks.0.type", ""), [f"{at}.type is not a non-empty string"]),
                ("type missing", set_at("statement.tasks.0.type", delete=True), [f"{at}.type is not a non-empty string"]),
                ("step_of a task that is not there", set_at("statement.tasks.1.step_of", "t9"), [step]),
                ("step_of itself", set_at("statement.tasks.1.step_of", "t1-land"), [step]),
                ("step_of a number", set_at("statement.tasks.1.step_of", 1), [step]),
                ("step_of missing", set_at("statement.tasks.1.step_of", delete=True), [step]),
                ("step_of a task of this statement", set_at("statement.tasks.2.step_of", "t1"), []),
                ("final_state", set_at("statement.tasks.0.final_state", 1), [f"{at}.final_state is not a string or null"]),
                ("final_state missing", set_at("statement.tasks.0.final_state", delete=True), [f"{at}.final_state is not a string or null"]),
                ("disposition", set_at("statement.tasks.0.disposition", []), [f"{at}.disposition is not a string or null"]),
                ("receipt", set_at("statement.tasks.0.receipt", "abc"), [f"{at}.receipt is not 64 lowercase hexadecimal characters, or null"]),
                ("receipt missing", set_at("statement.tasks.0.receipt", delete=True), [f"{at}.receipt is not 64 lowercase hexadecimal characters, or null"]),
                ("tries", set_at("statement.tasks.0.tries", None), [f"{at}.tries is not a list"]),
            ]
        )

    def test_each_try_is_checked(self) -> None:
        at = "statement.tasks[0].tries[0]"
        self.check_edits(
            [
                ("not an object", set_at("statement.tasks.0.tries.0", []), [f"{at} is not an object"]),
                ("attempt_id", set_at("statement.tasks.0.tries.0.attempt_id", ""), [f"{at}.attempt_id is not a non-empty string"]),
                ("agent", set_at("statement.tasks.0.tries.0.agent", delete=True), [f"{at}.agent is not a non-empty string"]),
                ("outcome", set_at("statement.tasks.0.tries.0.outcome", 1), [f"{at}.outcome is not a non-empty string"]),
                ("model", set_at("statement.tasks.0.tries.0.model", 1), [f"{at}.model is not a string or null"]),
                ("model missing", set_at("statement.tasks.0.tries.0.model", delete=True), [f"{at}.model is not a string or null"]),
                ("minutes negative", set_at("statement.tasks.0.tries.0.minutes", -1), [f"{at}.minutes is not a finite number of zero or more, or null"]),
                ("minutes a string", set_at("statement.tasks.0.tries.0.minutes", "1"), [f"{at}.minutes is not a finite number of zero or more, or null"]),
                ("minutes missing", set_at("statement.tasks.0.tries.0.minutes", delete=True), [f"{at}.minutes is not a finite number of zero or more, or null"]),
                ("usd_micros fractional", set_at("statement.tasks.0.tries.0.usd_micros", 0.5), [f"{at}.usd_micros is not a whole number of zero or more, or null"]),
                ("usd_micros negative", set_at("statement.tasks.0.tries.0.usd_micros", -1), [f"{at}.usd_micros is not a whole number of zero or more, or null"]),
                ("usd_micros missing", set_at("statement.tasks.0.tries.0.usd_micros", delete=True), [f"{at}.usd_micros is not a whole number of zero or more, or null"]),
                ("cost", set_at("statement.tasks.0.tries.0.cost", "free"), [f"{at}.cost is not metered, reported or unknown"]),
                ("cost missing", set_at("statement.tasks.0.tries.0.cost", delete=True), [f"{at}.cost is not metered, reported or unknown"]),
                ("unknown with a figure", set_at("statement.tasks.0.tries.0.cost", "unknown"), [f"{at}.cost is unknown, but its usd_micros is not null"]),
                ("a null figure with a cost", set_at("statement.tasks.0.tries.0.usd_micros", None), [f"{at}.usd_micros is null, but its cost is metered"]),
            ]
        )

    def test_a_try_of_a_task_after_the_first_is_named_by_both_indexes(self) -> None:
        document = changed(self.build(), set_at("statement.tasks.1.tries.0.minutes", -1))
        self.check_reasons(self.seal(document), ["statement.tasks[1].tries[0].minutes is not a finite number of zero or more, or null"])

    def test_each_total_is_checked(self) -> None:
        names = ("tries", "tries_unknown", "usd_micros_reported", "usd_micros_metered")
        edits = []
        for name in names:
            edits.append((f"{name} differs", set_at(f"statement.totals.{name}", 9), [f"statement.totals.{name} is not the sum of the tries"]))
            shape = [f"statement.totals.{name} is not a whole number of zero or more", f"statement.totals.{name} is not the sum of the tries"]
            edits.append((f"{name} negative", set_at(f"statement.totals.{name}", -1), shape))
            edits.append((f"{name} a string", set_at(f"statement.totals.{name}", "1"), shape))
            edits.append((f"{name} missing", set_at(f"statement.totals.{name}", delete=True), shape))
        self.check_edits(edits)

    def test_a_total_is_added_up_again_from_the_tries(self) -> None:
        document = changed(self.build(), lambda d: d["statement"]["tasks"][2]["tries"].append(copy.deepcopy(d["statement"]["tasks"][0]["tries"][1])))
        document["statement"]["tasks"][2]["tries"][0]["attempt_id"] = "a4"
        self.check_reasons(
            self.seal(document),
            ["statement.totals.tries is not the sum of the tries", "statement.totals.usd_micros_reported is not the sum of the tries"],
        )
        document["statement"]["totals"].update(tries=4, usd_micros_reported=4000000)
        self.check_valid(self.seal(document))

    def test_a_total_is_not_added_up_where_a_try_is_malformed(self) -> None:
        document = changed(self.build(), set_at("statement.tasks.0.tries.0.cost", "free"))
        document["statement"]["totals"]["tries"] = 99
        self.check_reasons(self.seal(document), ["statement.tasks[0].tries[0].cost is not metered, reported or unknown"])

    def test_a_sum_past_2_to_the_53_cannot_be_added_up_exactly(self) -> None:
        document = changed(self.build(), set_at("statement.tasks.0.tries.0.usd_micros", 2**53))
        document["statement"]["tasks"][0]["tries"][1].update(cost="metered")
        document["statement"]["totals"].update(usd_micros_reported=0, usd_micros_metered=2**53 + 2000000)
        self.check_reasons(self.seal(document), ["statement.totals cannot be added up exactly: a sum passes 2^53"])
        document["statement"]["tasks"][0]["tries"][1]["usd_micros"] = 0
        document["statement"]["totals"]["usd_micros_metered"] = 2**53
        self.check_valid(self.seal(document))

    def test_a_statement_may_list_no_tasks(self) -> None:
        document = changed(self.build(), lambda d: d["statement"].update(tasks=[], totals=dict.fromkeys(("tries", "tries_unknown", "usd_micros_reported", "usd_micros_metered"), 0)))
        self.check_valid(self.seal(document))

    def test_a_document_that_is_not_an_object_is_not_a_statement(self) -> None:
        self.assertEqual(CHECKS[self.schema]([], "[]"), ("project-statement", ["it is not a project statement: it is not a JSON object"]))


# ---------------------------------------------------------------------------------------------
# tick.hub-index.v1

INDEX_LABEL = "tick-hub-index:v1"


def hub_index() -> dict[str, Any]:
    index = {
        "publisher": "issuer:subject",
        "previous": None,
        "projects": [
            {
                "slug": "alpha",
                "name": "Alpha",
                "repository": "https://example.com/alpha.git",
                "runs": [
                    {"run_id": "run-1", "statements": [HASH_A, HASH_B], "head": HASH_B},
                    {"run_id": "run-2", "statements": [HASH_C], "head": HASH_C},
                ],
            },
            {
                "slug": "beta-2",
                "name": "Beta",
                "repository": "https://example.com/beta.git",
                "runs": [{"run_id": "run-1", "statements": [HASH_A], "head": HASH_A}],
            },
        ],
    }
    document = {
        "schema": "tick.hub-index.v1",
        "alg": "ed25519",
        "issued_at": "2026-10-20T09:00:00.000Z",
        "coordinator": "coordinator.example",
        "index": index,
        "limits": ["An index lists what its publisher chose to publish."],
    }
    return seal(document, "index", INDEX_LABEL)


class HubIndex(Signed, unittest.TestCase):
    kind, schema, noun = "hub-index", "tick.hub-index.v1", "index"
    body, body_reason = "index", "content_hash is not the hash of the index"
    signed_fields = ()
    build = staticmethod(hub_index)

    def seal(self, document: dict[str, Any]) -> dict[str, Any]:
        return seal(document, "index", INDEX_LABEL)

    def signed_message(self, document: dict[str, Any]) -> str:
        return f"{INDEX_LABEL}:{document['content_hash']}"

    def mutate_body(self, document: dict[str, Any]) -> None:
        document["index"]["publisher"] = "someone"

    def test_a_changed_signed_field_breaks_the_signature(self) -> None:
        document = changed(self.build(), set_at("content_hash", "0" * 64))
        self.assertIn("the signature is not the carried key’s over this index", verdict_of(document).reasons)

    def test_the_head_is_checked(self) -> None:
        self.check_edits(
            [
                ("issued_at", set_at("issued_at", "yesterday"), ["issued_at is not an ISO 8601 time"]),
                ("coordinator", set_at("coordinator", ""), ["coordinator is not a non-empty string"]),
                ("coordinator missing", set_at("coordinator", delete=True), ["coordinator is not a non-empty string"]),
            ]
        )

    def test_the_index_is_checked(self) -> None:
        self.check_edits(
            [
                ("publisher", set_at("index.publisher", ""), ["index.publisher is not a non-empty string"]),
                ("publisher missing", set_at("index.publisher", delete=True), ["index.publisher is not a non-empty string"]),
                ("previous", set_at("index.previous", "abc"), ["index.previous is not 64 lowercase hexadecimal characters, or null"]),
                ("previous missing", set_at("index.previous", delete=True), ["index.previous is not 64 lowercase hexadecimal characters, or null"]),
                ("previous a hash", set_at("index.previous", HASH_C), []),
                ("projects", set_at("index.projects", {}), ["index.projects is not a list"]),
                ("projects missing", set_at("index.projects", delete=True), ["index.projects is not a list"]),
            ]
        )
        for body in (None, [], "index"):
            with self.subTest(index=body):
                self.check_reasons(self.seal(changed(self.build(), set_at("index", body))), ["index is not an object"])
        self.check_reasons(changed(self.build(), set_at("index", delete=True)), ["index is not an object", "the index cannot be hashed"])

    def test_each_project_is_checked(self) -> None:
        at = "index.projects[0]"
        slug = f"{at}.slug is not lowercase letters and digits joined by single hyphens"
        edits = [
            ("not an object", set_at("index.projects.0", "alpha"), [f"{at} is not an object"]),
            ("name", set_at("index.projects.0.name", ""), [f"{at}.name is not a non-empty string"]),
            ("name missing", set_at("index.projects.0.name", delete=True), [f"{at}.name is not a non-empty string"]),
            ("repository", set_at("index.projects.0.repository", 1), [f"{at}.repository is not a non-empty string"]),
            ("runs", set_at("index.projects.0.runs", []), [f"{at}.runs is not a non-empty list"]),
            ("runs missing", set_at("index.projects.0.runs", delete=True), [f"{at}.runs is not a non-empty list"]),
            ("runs a twice", lambda d: d["index"]["projects"][0]["runs"].append(copy.deepcopy(d["index"]["projects"][0]["runs"][0])), [f"{at}.runs names one run twice"]),
            ("a slug of a valid form", set_at("index.projects.0.slug", "a-1-b"), []),
        ]
        for label, value in (("uppercase", "Alpha"), ("underscore", "a_b"), ("double hyphen", "a--b"), ("leading hyphen", "-a"), ("trailing hyphen", "a-"), ("empty", ""), ("space", "a b"), ("number", 1)):
            edits.append((f"slug {label}", set_at("index.projects.0.slug", value), [slug]))
        edits.append(("slug missing", set_at("index.projects.0.slug", delete=True), [slug]))
        self.check_edits(edits)

    def test_each_run_is_checked(self) -> None:
        at = "index.projects[0].runs[0]"
        statements = f"{at}.statements is not a non-empty list of 64 lowercase hexadecimal characters each"
        head = f"{at}.head is not the newest of its statements"
        self.check_edits(
            [
                ("not an object", set_at("index.projects.0.runs.0", 5), [f"{at} is not an object"]),
                ("run_id", set_at("index.projects.0.runs.0.run_id", ""), [f"{at}.run_id is not a non-empty string"]),
                ("run_id missing", set_at("index.projects.0.runs.0.run_id", delete=True), [f"{at}.run_id is not a non-empty string"]),
                ("statements empty", set_at("index.projects.0.runs.0.statements", []), [statements, head]),
                ("statements not a list", set_at("index.projects.0.runs.0.statements", HASH_A), [statements, head]),
                ("statements missing", set_at("index.projects.0.runs.0.statements", delete=True), [statements, head]),
                ("a statement not a hash", set_at("index.projects.0.runs.0.statements.0", "abc"), [statements]),
                ("a statement in uppercase", set_at("index.projects.0.runs.0.statements.0", "A" * 64), [statements]),
                ("the head a statement not a hash", set_at("index.projects.0.runs.0.statements.1", "abc"), [statements, head]),
                ("a statement twice", set_at("index.projects.0.runs.0.statements.0", HASH_B), [f"{at}.statements names one statement twice"]),
                ("head the oldest", set_at("index.projects.0.runs.0.head", HASH_A), [head]),
                ("head another", set_at("index.projects.0.runs.0.head", HASH_C), [head]),
                ("head null", set_at("index.projects.0.runs.0.head", None), [head]),
                ("head missing", set_at("index.projects.0.runs.0.head", delete=True), [head]),
            ]
        )

    def test_the_projects_are_unique_and_sorted_by_slug(self) -> None:
        def second(slug: str) -> Callable[[dict[str, Any]], None]:
            return set_at("index.projects.1.slug", slug)

        def swap(d: dict[str, Any]) -> None:
            d["index"]["projects"].reverse()

        self.check_edits(
            [
                ("a slug twice", second("alpha"), ["index.projects names one slug twice"]),
                ("not sorted", swap, ["index.projects is not sorted by slug"]),
                ("not sorted by slug", second("a"), ["index.projects is not sorted by slug"]),
                ("sorted by slug", second("alpha-2"), []),
                ("sorted, with digits", second("alpha1"), []),
            ]
        )
        # With a slug twice, the order is not reported as well.
        both = changed(self.build(), lambda d: d["index"]["projects"].insert(0, copy.deepcopy(d["index"]["projects"][1])))
        self.check_reasons(self.seal(both), ["index.projects names one slug twice"])

    def test_the_same_run_may_be_in_two_projects(self) -> None:
        self.check_valid(self.build())
        self.assertEqual(self.build()["index"]["projects"][0]["runs"][0]["run_id"], self.build()["index"]["projects"][1]["runs"][0]["run_id"])

    def test_a_document_that_is_not_an_object_is_not_an_index(self) -> None:
        self.assertEqual(CHECKS[self.schema]([], "[]"), ("hub-index", ["it is not an index: it is not a JSON object"]))


# ---------------------------------------------------------------------------------------------
# tick-keys/1


def keys_file() -> dict[str, Any]:
    return {
        "schema": "tick-keys/1",
        "keys": [
            {"key_id": KEY.key_id, "role": "coordinator", "from": "2026-01-15"},
            {"key_id": "0123456789abcdef", "role": "release", "from": "2026-02-28"},
        ],
        "limits": ["Its authority is the domain that serves it."],
    }


class KeysFile(Cases, unittest.TestCase):
    kind, schema = "keys-file", "tick-keys/1"
    build = staticmethod(keys_file)

    def test_the_keys_are_checked(self) -> None:
        at = "keys[0]"
        edits = [
            ("keys empty", set_at("keys", []), ["keys is not a non-empty list"]),
            ("keys an object", set_at("keys", {}), ["keys is not a non-empty list"]),
            ("keys missing", set_at("keys", delete=True), ["keys is not a non-empty list"]),
            ("a key not an object", set_at("keys.0", "a"), [f"{at} is not an object"]),
            ("a key twice", set_at("keys.1.key_id", KEY.key_id), ["keys names one key_id twice"]),
            ("a role of release", set_at("keys.0.role", "release"), []),
            ("a key_id missing", set_at("keys.0.key_id", delete=True), [f"{at}.key_id is not 16 lowercase hexadecimal characters"]),
            ("a role missing", set_at("keys.0.role", delete=True), [f"{at}.role is not coordinator or release"]),
            ("from missing", set_at("keys.0.from", delete=True), [f"{at}.from is not a day, YYYY-MM-DD"]),
        ]
        for label, value in (("short", "abcdef"), ("long", "0" * 17), ("uppercase", "A" * 16), ("not hex", "g" * 16), ("a number", 1234567890123456)):
            edits.append((f"key_id {label}", set_at("keys.0.key_id", value), [f"{at}.key_id is not 16 lowercase hexadecimal characters"]))
        for label, value in (("other", "owner"), ("case", "Coordinator"), ("empty", ""), ("null", None)):
            edits.append((f"role {label}", set_at("keys.0.role", value), [f"{at}.role is not coordinator or release"]))
        for label, value in (("not a day", "yesterday"), ("a time", "2026-01-15T00:00:00Z"), ("no day", "2026-01"), ("no zero", "2026-1-5"), ("no such day", "2026-02-30"), ("no such month", "2026-13-01"), ("a number", 20260115), ("null", None)):
            edits.append((f"from {label}", set_at("keys.0.from", value), [f"{at}.from is not a day, YYYY-MM-DD"]))
        self.check_edits(edits)

    def test_every_wrong_entry_is_reported(self) -> None:
        document = changed(self.build(), lambda d: d["keys"].append({"key_id": KEY.key_id, "role": "x", "from": "never"}))
        self.check_reasons(
            document,
            ["keys[2].role is not coordinator or release", "keys[2].from is not a day, YYYY-MM-DD", "keys names one key_id twice"],
        )

    def test_a_document_that_is_not_an_object_is_not_a_keys_file(self) -> None:
        self.assertEqual(CHECKS[self.schema]([], "[]"), ("keys-file", ["it is not a keys file: it is not a JSON object"]))



class Table(unittest.TestCase):
    def test_every_schema_of_the_specification_is_checked(self) -> None:
        self.assertEqual(
            set(CHECKS),
            {
                "tick.receipt.v1", "tick.audit-export.v1", "tick.audit-trail-export.v1", "tick.usage-report.v1",
                "tick.work-order.v1", "tick.delivery.v1", "tick.check-record.v1", "tick.receipt.v2",
                "tick.release-receipt.v1", "tick.project-receipt.v2", "tick.hub-index.v1", "tick-keys/1",
            },
        )  # fmt: skip
        self.assertEqual(NOT_JSON_OBJECT, verify_document("[]").reasons[0])


if __name__ == "__main__":
    unittest.main()

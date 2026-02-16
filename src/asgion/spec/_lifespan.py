from asgion.spec._checks import FieldType
from asgion.spec._protocol import EventSpec, ProtocolSpec

LIFESPAN_SPEC = ProtocolSpec(
    name="lifespan",
    layer="lifespan.events",
    invalid_receive_rule_id="LE-001",
    invalid_receive_summary="Invalid lifespan receive event type",
    invalid_send_rule_id="LE-003",
    invalid_send_summary="Invalid lifespan send event type",
    events=(
        EventSpec("lifespan.startup", "receive"),
        EventSpec("lifespan.shutdown", "receive"),
        EventSpec("lifespan.startup.complete", "send"),
        EventSpec(
            "lifespan.startup.failed",
            "send",
            checks=(FieldType("message", str, "LE-004"),),
        ),
        EventSpec("lifespan.shutdown.complete", "send"),
        EventSpec(
            "lifespan.shutdown.failed",
            "send",
            checks=(FieldType("message", str, "LE-006"),),
        ),
    ),
)

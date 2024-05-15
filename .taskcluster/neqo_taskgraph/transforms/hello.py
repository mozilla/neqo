from voluptuous import ALLOW_EXTRA, Required

from taskgraph.transforms.base import TransformSequence
from taskgraph.util.schema import Schema

transforms = TransformSequence()

HELLO_SCHEMA = Schema(
    {
        Required("noun"): str,
    },
    extra=ALLOW_EXTRA,
)

transforms = TransformSequence()
transforms.add_validate(HELLO_SCHEMA)


@transforms.add
def add_noun(config, tasks):
    for task in tasks:
        noun = task.pop("noun").capitalize()
        task["description"] = f"Prints 'Hello {noun}'"

        env = task.setdefault("worker", {}).setdefault("env", {})
        env["NOUN"] = noun

        yield task

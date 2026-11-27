"""Shared helpers for generated unittest cases."""
from __future__ import annotations


def safe_name(value, fallback="case"):
    text = "".join(character.lower() if character.isalnum() else "_" for character in str(value))
    text = "_".join(part for part in text.split("_") if part)
    return (text or fallback)[:70]


def add_generated_tests(cls, prefix, values, body):
    for index, value in enumerate(values):
        name = "test_" + prefix + "_" + str(index).zfill(3) + "_" + safe_name(value)

        def generated(self, value=value):
            body(self, value)

        generated.__name__ = name
        setattr(cls, name, generated)
    return cls

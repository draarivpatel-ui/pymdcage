"""Internal helpers for enforcing frozen dataclass field immutability."""
from __future__ import annotations

import dataclasses
import functools
import threading
import weakref
from typing import Any, Dict, Set, Type, TypeVar

_T = TypeVar("_T")

_lock = threading.RLock()
_values: Dict[int, Dict[str, Any]] = {}
_constructing: Set[int] = set()
_completed: Set[int] = set()
_registered: Set[int] = set()


def _cleanup(identity: int) -> None:
    with _lock:
        _values.pop(identity, None)
        _constructing.discard(identity)
        _completed.discard(identity)
        _registered.discard(identity)


def _register_instance(instance: Any, identity: int) -> None:
    if identity in _registered:
        return
    _registered.add(identity)
    _values[identity] = {}
    weakref.finalize(instance, _cleanup, identity)


def harden_frozen_dataclass(cls: Type[_T]) -> Type[_T]:
    """Block direct and indirect writes to declared frozen dataclass fields.

    Values are kept in identity-keyed storage rather than in the instance
    dictionary. This means ``object.__setattr__`` cannot overwrite either the
    visible field property or a hidden backing field.
    """

    original_init = cls.__init__
    field_names = tuple(field.name for field in dataclasses.fields(cls))

    for field_name in field_names:

        def getter(self: Any, field_name: str = field_name) -> Any:
            identity = id(self)
            with _lock:
                values = _values.get(identity)
                if values is not None and field_name in values:
                    return values[field_name]
            raise AttributeError(field_name)

        def setter(self: Any, value: Any, field_name: str = field_name) -> None:
            identity = id(self)
            with _lock:
                if identity in _constructing:
                    _register_instance(self, identity)
                    _values[identity][field_name] = value
                    return
            raise dataclasses.FrozenInstanceError("cannot assign to field " + repr(field_name))

        setattr(cls, field_name, property(getter, setter))

    @functools.wraps(original_init)
    def guarded_init(self: Any, *args: Any, **kwargs: Any) -> None:
        identity = id(self)
        with _lock:
            if identity in _completed:
                raise dataclasses.FrozenInstanceError("cannot reinitialize a frozen instance")
            _register_instance(self, identity)
            _constructing.add(identity)
        try:
            original_init(self, *args, **kwargs)
        finally:
            with _lock:
                _constructing.discard(identity)
                if identity in _values:
                    _completed.add(identity)

    cls.__init__ = guarded_init
    return cls

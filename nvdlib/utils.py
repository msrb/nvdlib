"""Module containing utilities for nvdlib package."""

import operator

from collections import Mapping

# NOTE: Victims does not support ``[<>]`` regex
SYMBOLS = ['==', '<', '<=', '>=', '>']
OPERATORS = [
    operator.eq, operator.lt, operator.le, operator.ge, operator.gt,
]
OPERATOR_DICT = dict(zip(SYMBOLS, OPERATORS))


class AttrDict(Mapping):
    """A class to convert a nested Dictionary into an object with key-values
    accessibly using attribute notation (AttributeDict.attribute) instead of
    key notation (Dict["key"]).

    This class recursively sets Dicts to objects, allowing to recurse down
    the nested dicts (like: AttributeDict.attr.attr)
    """
    def __init__(self, **entries):
        for key, value in entries.items():
            # replace dashes by underscores JIC
            key = key.replace('-', '_')
            if type(value) is dict:
                self.__dict__[key] = AttrDict(**value)
            else:
                self.__dict__[key] = value

    def __iter__(self):
        for k in self.__dict__:
            yield k

    def __len__(self):
        return len(self.__dict__)

    def __str__(self):
        return self.__dict__.__str__()

    def __repr__(self):
        return self.__dict__.__repr__()

    def __getitem__(self, key):
        """
        Provides dict-style access to attributes
        """
        return getattr(self, key)


def get_victims_notation(version_tuple: list):
    """Maps version range tuple to corresponding victims string notation.
    Assumes arguments ``version_range`` is a tuple or a sequence
    ``(versionExact, versionEndExcluding, versionEndIncluding, versionStartIncluding, versionEndExcluding)``

    :returns: str, victims notation of version ranges (see https://github.com/victims/victims-cve-db)
    """
    if len(version_tuple) != len(SYMBOLS) or len(version_tuple) > 5:
        raise AttributeError("shape of ``version_tuple`` does not match shape of ``SYMBOLS``."
                             " Expected shapes (5,) == (5,), got: %r != %r" % (len(version_tuple), len(SYMBOLS)))

    # Check if an exact version is selected, in that case no version range is allowed
    if version_tuple[0] and any(version_tuple[1:]):
        raise AttributeError("``version_tuple`` contains both exact version and version range, which is not allowed.")

    indices = [i for i, val in enumerate(version_tuple) if val is not None]
    notation = [str(SYMBOLS[i]) + str(version_tuple[i]) for i in indices]

    return ",".join(notation)

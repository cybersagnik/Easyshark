"""Permission tiers for autonomous actions."""
from __future__ import annotations

from enum import IntEnum


class ActionTier(IntEnum):
    READ_ONLY = 0
    GENERATE = 1
    MODIFY_LOCAL = 2
    EXTERNAL_NOTIFY = 3
    NETWORK_CHANGE = 4


def authorize(tier: ActionTier, approved: bool = False,
              max_tier: ActionTier = ActionTier.GENERATE) -> bool:
    """Return whether an action is allowed under the current policy."""
    if not isinstance(tier, ActionTier):
        raise TypeError("tier must be an ActionTier")
    return tier <= max_tier or approved

from enum import Enum


class ReproductionMode(str, Enum):
    CRASH = "crash"
    FIX = "fix"

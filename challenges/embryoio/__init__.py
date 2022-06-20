from importlib import import_module

NUM_CHALLS = 1
CHALLENGES = [getattr(import_module("." + str(i).zfill(3), package=__name__), f"Chall{i}")() for i in range(1, NUM_CHALLS + 1)]

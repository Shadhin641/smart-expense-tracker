from django.contrib.auth.hashers import Argon2PasswordHasher


class FastArgon2Hasher(Argon2PasswordHasher):
    """Same algorithm (argon2id) with cheap parameters so the test suite stays fast."""

    time_cost = 1
    memory_cost = 1024
    parallelism = 1

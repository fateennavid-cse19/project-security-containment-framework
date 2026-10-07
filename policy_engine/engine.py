from policy_engine.policy import SENSITIVE_DATA_EXTERNAL


class PolicyEngine:
    def __init__(self):
        self.policies = [
            SENSITIVE_DATA_EXTERNAL
        ]

    def get_policies(self):
        return self.policies
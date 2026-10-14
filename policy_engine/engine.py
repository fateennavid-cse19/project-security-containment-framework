from policy_engine.policy import SENSITIVE_DATA_EXTERNAL


class PolicyEngine:

    """Manages the security policies used to identify prohibited
    capability paths within the multi-agent system.
    """

    def __init__(self):

        """Initialise the engine with the currently defined security policies."""
        
        self.policies = [
            SENSITIVE_DATA_EXTERNAL
        ]

    def get_policies(self):
        return self.policies
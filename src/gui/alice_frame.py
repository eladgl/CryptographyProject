from .userFrame import UserFrame

class AliceFrame(UserFrame):
    def __init__(self, master, controller, recipients):
        super().__init__(master, controller, bg_color="lightblue", title="Alice", recipients=recipients)

    def send_message(self, message, recipient):
        """Send the encrypted message to Bob."""
        self.controller.shared_state["bob_message"] = message
        self.selected_recipient = recipient

    def get_message(self):
        """Get the encrypted message from Bob."""
        return self.controller.shared_state["alice_message"]
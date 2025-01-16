from .userFrame import UserFrame
import base64
class BobFrame(UserFrame):
    def __init__(self, master, controller, recipients):
        super().__init__(master, controller, bg_color="lightgreen", title="Bob", recipients=recipients)

    def send_message(self, message, recipient):
        """Send the encrypted message to Alice."""
        self.controller.shared_state["alice_message"] = message
        self.selected_recipient = recipient

    def get_message(self):
        """Get the encrypted message from Alice."""
        bob_message = self.controller.shared_state["bob_message"]
        if isinstance(bob_message, bytes):
            return base64.b64encode(bob_message).decode("utf-8")
        return bob_message

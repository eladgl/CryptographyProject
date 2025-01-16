from .userFrame import UserFrame
import base64
class AliceFrame(UserFrame):
    def __init__(self, master, controller, recipients):
        super().__init__(master, controller, bg_color="lightblue", title="Alice", recipients=recipients)
        self.message = ''

    def send_message(self, message, recipient):
        """Send the encrypted message to Bob."""
        self.controller.shared_state["bob_message"] = message
        self.selected_recipient = recipient

    def get_message(self):
        """Get the encrypted message from Bob."""
        alice_message = self.controller.shared_state["alice_message"]
        if isinstance(alice_message, bytes):
            return base64.b64encode(alice_message).decode("utf-8")
        return alice_message
    
    def set_message(self, message):
        return super().set_message(message)

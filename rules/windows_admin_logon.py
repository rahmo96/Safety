from base_rule import SecurityRule

class WindowsAdminLogonRule(SecurityRule):
    def __init__(self):
        # כאן התיקון: מעבירים את הערכים שהמחלקה SecurityRule דורשת
        super().__init__(
            rule_name="Windows Privileged Logon", 
            severity="medium"
        )

    def evaluate(self, log_entry):
        # בדיקה אם זה אירוע של כניסת אדמין/הרשאות מיוחדות בווינדוס
        # אנחנו תומכים בשם השדה כפי שהוא מופיע ב-secW.csv שלך
        event_id = str(log_entry.get('event_id', ''))
        
        if event_id == '4672':
            return {
                "type": "Admin_Logon_Detected",
                "severity": self.severity,
                "timestamp": log_entry.get('timestamp'),
                "description": "Special privileges assigned to a new logon (Event 4672)"
            }
        return None
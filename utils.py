'''
Utility functions
'''
def html_red(text):
    """Apply red CSS style to text.

    Args:
        text (str): Text to surround with style
    """
    return f'<a style="color: red;">{text}</a>'

def html_status(audit_status):
    """Apply red or green CSS style based on audit status

    Args:
        audit_status (str): AUDIT_PASS or AUDIT_FAIL
    """
    if audit_status == "AUDIT_PASS":
        return f'<a style="color: lime; font-weight: bold;">{audit_status.strip("AUDIT_")}</a>'
    if audit_status == "AUDIT_FAIL":
        return f'<a style="color: red; font-weight: bold;">{audit_status.strip("AUDIT_")}</a>'
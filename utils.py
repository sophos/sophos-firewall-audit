'''
Utility functions
'''
import re

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
    
def format_diff(diff):
    """Remove lines with ---, +++, @@ and style diff lines in red.

    Args:
        diff (list): A list containing the diff

    Returns:
        list: formatted output
    """
    output = []
    for line in diff:
        patterns = ["-{3}", r"\+{3}", r"\@{2}"]
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                break
        if not match:
            if line.startswith("-") or line.startswith("+"):
                output.append(html_red(line))
            else:
                output.append(line)
    return output
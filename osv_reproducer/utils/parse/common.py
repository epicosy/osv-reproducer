from typing import List, Dict, Any, Optional


def create_frame(function: str, file: str = "", message_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a frame dictionary for a stack trace.

    Args:
        function: Function name
        file: File name or module
        message_text: Custom message text (if None, a default message will be created)

    Returns:
        dict: Frame dictionary
    """
    if message_text is None:
        message_text = f"in {function}" + (f" ({file})" if file else "")

    # Create a location dictionary
    location = {
        "logical_locations": [
            {
                "name": function
            }
        ],
        "message": {
            "text": message_text
        }
    }

    # Create a frame dictionary
    return {
        "location": location,
        "module": file
    }


def create_stack_dict(frames: List[Dict[str, Any]], message_text: str = "Stack trace from crash") -> Dict[str, Any]:
    """
    Create a stack dictionary from a list of frames.

    Args:
        frames: List of frame dictionaries
        message_text: Message text for the stack

    Returns:
        dict: Stack dictionary
    """
    return {
        "frames": frames,
        "message": {
            "text": message_text
        }
    }
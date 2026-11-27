def compact(prefix: str, *, text: str = ""):
    label = prefix
    for char in text:
        if char.isalnum():
            label += char
    return label

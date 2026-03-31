from django import forms


class URLForm(forms.Form):
    url = forms.URLField(
        label="",
        max_length=2000,
        widget=forms.URLInput(attrs={
            "placeholder": "https://example.com",
            "class": "url-input",
            "autofocus": True,
        }),
        error_messages={
            "required": "Please enter a URL.",
            "invalid": "Enter a valid URL starting with http:// or https://",
        },
    )

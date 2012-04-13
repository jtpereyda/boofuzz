import os

__all__ = []

for filename in os.listdir(os.path.dirname(__file__)):
    if not filename.startswith("__") and filename.endswith(".py"):
        filename = filename.replace(".py", "")
        __all__.append(filename)

        # uncommenting the next line causes all requests to load into the namespace once 'requests' is imported.
        # this is not the desired behaviour, instead the user should import individual packages of requests. ie:
        #   from requests import http, trend

        #__import__("requests."+filename)

__version__ = "0.1.0a4"


def _jupyter_server_extension_points():
    from .server_extension import SMARTExtensionApp

    return [
        {"module": "jupyter_smart_on_fhir.server_extension", "app": SMARTExtensionApp}
    ]

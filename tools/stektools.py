import calendar
import cbor2
import datetime
import os


def stek_generate(service_name, valid_from, valid_to):
    """
    Generate a properly formatted STEK file
    """
    stek_dict = {
        'version': 1,
        'serviceName': service_name,
        'validFrom': calendar.timegm(valid_from.timetuple()),
        'validTo': calendar.timegm(valid_to.timetuple()),
        'wrapKey': os.urandom(32),
        'hmacKey': os.urandom(32)
    }
    return cbor2.dumps(stek_dict)


import logging

import fire

from .defaults import load_config, RequestError
from zia import ZscalerInternetAccess


def main():
    load_config()
    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(logging.DEBUG)
    try:
        z = ZscalerInternetAccess()
        z.authenticate()
        fire.Fire(z)
    except RequestError as exc:
        LOGGER.error(exc)
    return 0


if __name__ == "__main__":
    main()

import logging

logger = logging.getLogger(__name__)


def log_info():
    logging.basicConfig(
        filename="log.txt",
        format="%(asctime)s %(levelname)s : %(message)s ",
        level=logging.INFO,
    )


def log_warning():
    logging.basicConfig(
        filename="log.txt",
        format="%(asctime)s %(levelname)s : %(message)s ",
        level=logging.WARNING,
    )


def start():
    log_info()
    logger.info("Starting Bulk Scan")
    return "Starting Bulk Scan"


def end():
    log_info()
    logger.info("Bulk Scan Completed")
    return "Bulk Scan Completed"


def process(target):
    log_info()
    logger.info(f"Retriving info about {target}")
    return f"Retriving info about {target}"


def judgement(info):

    if info["Status"] == "Public":
        if info["Safety Status"] == "Safe":
            log_info()
            logger.info(f"{info['Input']} is Safe")
            return f"{info['Input']} is Safe"
        elif info["Safety Status"] == "Suspicious":
            log_info()
            logger.info(f"{info['Input']} is Suspicious")
            return f"{info['Input']} is Suspicious"
        else:
            log_warning()
            logger.warning(f"{info['Input']} is Malicious")
            return f"{info['Input']} is Malicious"

    else:
        log_info()
        logger.info(f"{info['Input']} is {info['Status']}")
        return f"{info['Input']} is {info['Status']}"

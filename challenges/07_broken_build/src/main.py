import utils

def run():
    # Needs tests!
    # Depends on utils which depends on a missing file path in docker-compose
    data = utils.load_config()
    return f"Processed {data}"

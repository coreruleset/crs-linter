def get_id(actions):
    """ Return the ID from actions """
    for a in actions:
        if a["act_name"] == "id":
            return int(a["act_arg"])
    return 0

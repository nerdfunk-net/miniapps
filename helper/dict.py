
def get_value_from_dict(dictionary, keys):

    if dictionary is None:
        return None

    nested_dict = dictionary

    for key in keys:
        try:
            nested_dict = nested_dict[key]
        except KeyError as e:
            return None
        except IndexError as e:
            return None

    return nested_dict




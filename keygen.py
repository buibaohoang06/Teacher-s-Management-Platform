class KeyGen:
    def spawn():
        import random
        import string
        # With combination of lower and upper case
        result_str = ''.join(random.choice(string.ascii_letters) for i in range(8))
        # print random string
        return result_str

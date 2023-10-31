class Region:
    def __init__(self, name):
        self.name = name
        self.start = None
        self.end = None
        self.instructionCount = 0
        self.recursions = 0
        self.loops = 0
        self.conditionals = 0
        self.links = 0

    def __init__(self, name, start):
        self.name = name
        self.start = start
        self.end = None
        self.instructionCount = 0
        self.recursions = 0
        self.loops = 0
        self.conditionals = 0
        self.links = 0
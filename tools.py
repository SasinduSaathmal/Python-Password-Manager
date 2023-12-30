from typing import Literal, Union


class HandleFiles(object):
    def __init__(self, method: Literal['r', 'w', 'a', 'ab', 'cl', 'rb', 'wb', 'BACKUP'], file: str = "", key: bool = False, mp: bool = False, content: bool = False, all: bool = False, lines: bool = False, body: str = ""):
        METHODS = ['r', 'w', 'a', 'ab', 'cl', 'rb', 'wb', 'BACKUP']
        if not (method in METHODS):
            raise ValueError("The specified method is not valid.")
        self.body = body
        self.lines = lines
        if not file == "":
            key, mp, content = self.filter(file)

        self.content_list = []
        self.content: Union[str, int, bytes,
                            list[bytes], list[str], bytes, None] = None
        if not method == 'BACKUP':
            check = self.check(key, mp, content, all, method)
            self.content_list = self.sort(check, method)

        self.backup_content = ""

    def check(self, key, mp, content, all, method):
        if all == True:
            return "key", "mp", "content"

        elif key == True:
            if mp == True:
                return "key", "mp"
            elif content == True:
                return "key", "content"
            else:
                return "key"

        elif mp == True:
            if content == True:
                return "mp, content"
            else:
                return "mp"

        elif content == True:
            return "content"

        else:
            return None

    def filter(self, file):
        key = False
        mp = False
        content = False

        if file == "mp":
            mp = True
        elif file == "content":
            content = True
        else:
            key = True

        return key, mp, content

    def sort(self, check, method):
        content_list = []
        tcheck: str
        if check == None:
            return
        else:
            for i in ["key", "mp", "content"]:
                if i in check:
                    tcheck = f"lib/{i}"
                    if "r" in method:
                        if method == "rb":
                            self.readb(tcheck)
                        else:
                            self.read(tcheck)
                        content_list.append(self.content)

                    elif "w" in method:
                        if method == "wb":
                            self.writeb(tcheck, self.body)
                        else:
                            self.write(tcheck, self.body)
                        content_list.append(self.content)

                    elif "a" in method:
                        if method == "ab":
                            self.appendb(tcheck, self.body)
                        else:
                            self.append(tcheck, self.body)
                        content_list.append(self.content)

                    elif method == "cl":
                        self.clear(tcheck)

        return content_list

    def read(self, fname):
        with open(fname, "r") as file:
            if self.lines == False:
                self.content = file.read()
            else:
                self.content = file.readlines()

    def readb(self, fname):
        with open(fname, "rb") as file:
            if self.lines == False:
                self.content = file.read()
            else:
                self.content = file.readlines()

    def write(self, fname, content):
        with open(fname, "w") as file:
            if self.lines == False:
                self.content = file.write(content)
            else:
                self.content = file.writelines(content)

    def writeb(self, fname, content):
        with open(fname, "wb") as file:
            if self.lines == False:
                self.content = file.write(content)
            else:
                self.content = file.writelines(content)

    def append(self, fname, content):
        with open(fname, "a") as file:
            if self.lines == False:
                self.content = file.write(content)
            else:
                self.content = file.writelines(content)

    def appendb(self, fname, content):
        with open(fname, "ab") as file:
            if self.lines == False:
                self.content = file.write(content)
            else:
                self.content = file.writelines(content)

    def writeBackup(self, content: bytes):
        with open("lib/pwm-backup.bak", "wb") as file:
            file.write(content)

    def readBackup(self):
        with open("lib/pwm-backup.bak", "r") as file:
            backup_content = file.read()
            self.backup_content = backup_content

    def clear(self, fname):
        with open(fname, "w") as file:
            self.content = file.write("")


def byteReplacer(input, replacements: Union[dict, list], replaceByNone: bool = False, returnList: bool = False):
        input = str(input)
        output_list = []

        if replaceByNone == True:
            keys = replacements
            for _ in range(len(keys)):
                for i in keys:
                    value = ""
                    input = input.replace(i, value)
                    output_list.append(input)

        else:
            keys = list(replacements.keys())
            for _ in range(len(keys)):
                for i in keys:
                    value = replacements.get(i)
                    input = input.replace(i, value)
                    output_list.append(input)

        if returnList == True:
            return output_list
        else:
            output = output_list.pop()
            return output

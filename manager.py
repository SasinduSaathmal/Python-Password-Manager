from cryptography.fernet import Fernet
from getpass import getpass
from typing import Literal, Union
from typing_extensions import TypeAlias
from tools import HandleFiles, byteReplacer
from backup import BackupHandler
import os
import datetime
import sys


class Manager(object):
    def __init__(self):
        self.name = "mgr"
        self.stat = ["MAIN", "MASTER", "ADD",
                     "REMOVE", "SHOW", "RESET", "CLS", "CLEAR", "BACKUP"]
        self.file_handler = HandleFiles

        # print(self.file_handler("rb", key=True).content)

        if not("key" in os.listdir("lib/")):
            self.file_handler("w", key=True, body="")

        if not("content" in os.listdir("lib/")):
            self.file_handler("w", content=True, body="")

        if not("mp" in os.listdir("lib/")):
            self.file_handler("w", mp=True, body="")

        mp_content = self.file_handler("rb", mp=True).content
        if mp_content == "":
            self.present_master_password = False
        else:
            self.present_master_password = True

        key_content = self.file_handler("rb", key=True).content
        if key_content == bytes():
            print("Key is not set.\nGenerating a new key.")
            self._generateKey()

        if self.present_master_password == False:
            print("Master Password is not set.")
            try:
                self.setMasterPassword()
            except KeyboardInterrupt:
                print("Master Password is not set!")
                sys.exit()

    def getInput(self, prompt, confirm=False, pw: bool = False):
        if confirm == True:
            prompt_msg = f"Confirm {prompt} : "
        else:
            prompt_msg = f"Enter {prompt} : "
        if pw == True:
            input_msg = getpass(prompt_msg)
        else:
            input_msg = input(prompt_msg)
        return input_msg

    def status(self, stat):
        status = stat.upper()
        if status in self.stat:
            if status == self.stat[0]:
                return "MAIN"
            elif status == self.stat[1]:
                self.handleMaster()
            elif status == self.stat[2]:
                self.addPassword()
            elif status == self.stat[3]:
                self.removePassword()
            elif status == self.stat[4]:
                self.showPassword()
            elif status == self.stat[5]:
                self.reset()
            elif (status == self.stat[6]) or (status == self.stat[7]):
                self.clear()
            elif status == self.stat[8]:
                self.handleBackup()
        else:
            print("Invalid Input.")

    def _generateKey(self):
        key = Fernet.generate_key()
        self.file_handler("wb", key=True, body=key)
        print("Encryption key generated.")

    def addPassword(self):
        check = self.checkMasterPassword()
        if check == True:
            print("Type exit/quit to exit the context.")
            while True:
                uname = self.getInput(
                    "User-Name(This should be an identifier to identify the passwords uniquely.)")
                c = self._checkUname(uname)
                if (uname.upper() == "EXIT") or (uname.upper() == "QUIT"):
                    return
                elif c == 1:
                    print("Username is already in the password list.")
                else:
                    break

            while True:
                password = self.getInput("Password")
                c_password = self.getInput("Password", confirm=True)
                c = self._checkUname(uname)
                if (password.upper() == "EXIT") or (password.upper() == "QUIT"):
                    return
                elif c == 1:
                    print("Username is already in the password list.")
                elif password == c_password:
                    break
                else:
                    print("Passwords do not match!\nRe enter the password.")
                    continue

            time = datetime.datetime.now().strftime("%Y.%m.%d %H:%M:%S")
            self._encryptPassword(password, uname, time)
            print("Password successfuly added!")

        else:
            print("Password check falied!")

    def removePassword(self):
        check = self.checkMasterPassword()
        if check == True:
            print("Type exit/quit to exit the context.")
            while True:
                uname = self.getInput("User-Name")
                c = self._checkUname(uname)
                if (uname.upper() == "EXIT") or (uname.upper() == "QUIT"):
                    return
                elif c == 0:
                    print("Username is not found in the password list.")
                else:
                    break

            phrases = self.file_handler("rb", content=True, lines=True).content

            line_number = self._checkUname(uname, r=True)

            for local_index, i in enumerate(phrases):
                if local_index == line_number:
                    phrases.remove(i)

            self.file_handler("wb", content=True, lines=True, body=phrases)

            print("Password successfully removed.")

        else:
            print("Password check falied!")

    def showPassword(self):
        check = self.checkMasterPassword()
        self.clear()
        if check == True:
            n_records = self._checkRecords()
            print("Type exit/quit to exit the context.")
            print(f"You have {n_records} password(s) stored.")
            while True:
                uname = self.getInput("User-Name")
                c = self._checkUname(uname)
                if (uname.upper() == "EXIT") or (uname.upper() == "QUIT"):
                    return
                elif c == 0:
                    print("Username is not found in the password list.")
                else:
                    break

            password = self._decryptPassword(uname)
            # Replace b'' in the displaying passwords & create a global class method
            # for that to make our work easy. eg: def _byteRepalcer(self):
            print(password)
            self.clear(True)

        else:
            print("Password check falied!")

    def clear(self, inp: bool = False):
        if inp == True:
            input()
        os.system("cls")
        print("\n")
        return

    def checkMasterPassword(self):
        decrypted_password = self._decrypt("mp")
        while True:
            try:
                password = self.getInput(
                    "Master Password to continue", pw=True)
            except KeyboardInterrupt:
                return False
            if (password.upper() == "EXIT") or (password.upper() == "QUIT"):
                return False
            bytes_password = bytes(password, encoding="utf-8")
            if decrypted_password == bytes_password:
                return True
            else:
                print("Incorrect Password")
                return False

    def setMasterPassword(self):
        while True:
            password = self.getInput("Master Password to set")
            if (password.upper() == "EXIT") or (password.upper() == "QUIT"):
                return
            else:
                confimation = self.getInput("Master Password", True)
                if password == confimation:
                    break
                else:
                    print("Password and confirmation do not match!")

        key = self.file_handler("rb", key=True).content

        bytes_password = bytes(password, encoding="utf-8")
        encrypted_password = Fernet(key).encrypt(bytes_password)

        self.file_handler("wb", mp=True, body=encrypted_password)

        self.clear()

        print("Master Password has been set.")

    def removeMasterPassword(self):
        decrypted_password = self._decrypt("mp")
        while True:
            print("If you do not remember the password, reset it.(see help)")
            password = self.getInput("Master Password to remove", True)
            if (password.upper() == "EXIT") or (password.upper() == "QUIT"):
                return
            bytes_password = bytes(password, encoding="utf-8")
            if decrypted_password == bytes_password:
                break
            else:
                print("Incorrect Password")

        self.file_handler("cl", mp=True)

        print("Password successfully removed.")
        print("Now re-set the password.")
        self.setMasterPassword()

    def handleMaster(self):
        help = ("""
Master Password help:
    set     - sets master password
    remove  - removes master password(you will be asked to make a new one
              once you remove the password.)
    help    - shows this help menu
    exit    - exits the current context
    quit    - exits the current context
    """)
        print(help)
        print("Type exit/quit to exit the context.")
        while ((usr_input := input("MASTER> ").upper()) != "EXIT") or (usr_input != "QUIT"):
            # usr_input = input("MASTER>")
            upper = usr_input.upper()
            # if (upper == "EXIT") or (upper == "QUIT"):
            #     return
            if upper == "SET":
                self.setMasterPassword()
                break
            elif upper == "REMOVE":
                self.removeMasterPassword()
                break
            elif upper == "HELP":
                print(help)
            else:
                break
        return

    def reset(self):
        check = self.checkMasterPassword()
        if check == True:
            usr_input = input(
                "You are trying to reset all the data in the program\nincluding encryption key, passwords and master password.\nDo you wish to proceed? (yes/no): ")
            if usr_input.lower() == "yes":
                files = ["key", "content", "mp"]
                for file in files:
                    self.file_handler("cl", file)
                    print(
                        f"The file '{file.name}' was successfully cleared.")
                print("All the data has been successfullly cleared.")
                return
            else:
                print("User aborted the password reset process.")
                return
        else:
            print("Password check falied!")

    def _encryptPassword(self, password, uname, time, r: bool = False):
        bytes_password = bytes(password, encoding="utf-8")
        bytes_uname = bytes(uname, encoding="utf-8")
        key_content = self.file_handler("rb", key=True).content

        encrypted_password = Fernet(key_content).encrypt(bytes_password)
        encrypted_uname = Fernet(key_content).encrypt(bytes_uname)
        content = f"{encrypted_uname} : {encrypted_password}\n"
        bytes_content = bytes(content, encoding="utf-8")
        self.file_handler("ab", content=True, body=bytes_content)

        if r == True:
            return [encrypted_uname, encrypted_password]

    def _encrypt(self, content):
        bytes_content = bytes(content, encoding="utf-8")
        key_content = self.file_handler("rb", key=True).content

        encrypted_content = Fernet(key_content).encrypt(bytes_content)

        return encrypted_content

    def _decryptPassword(self, uname, run=False):
        def _popChar(input):
            input = str(input)
            s_input = list(input)
            s_input.pop()
            output = "".join(s_input)
            return output

        r = ['b"', "b'", "'", "\\n", '"']
        # r2 = ["b'", "'", "\\n", '"']
        decrypted_password_string = "{} : {}"
        key_content = self.file_handler("rb", key=True).content

        content = self.file_handler("r", content=True, lines=True).content

        for i in content:
            iterated_content = i
            phrase = str(iterated_content)
            encrypted_uname, encrypted_password = phrase.split(":")

            # replaced_encrypted_uname = encrypted_uname.replace(
            # 'b"', '').replace("b'", "").replace("'", "").replace("\\n", "")
            # replaced_encrypted_password = encrypted_password.replace(
            # "b'", "").replace("'", "").replace('\\n', '').replace('"', "")
            replaced_encrypted_uname = byteReplacer(
                encrypted_uname, r, True)
            replaced_encrypted_password = byteReplacer(
                encrypted_password, r, True)

            decrypted_uname = Fernet(key_content).decrypt(
                bytes(replaced_encrypted_uname, encoding="utf-8"))
            decrypted_password = Fernet(
                key_content).decrypt(bytes(replaced_encrypted_password, encoding="utf-8"))

            # replaced_decrypted_password = str(
            #     decrypted_password).replace("b'", '').replace("'", "")
            rn = ['b"', "b'", "\\n"]
            replaced_decrypted_password = byteReplacer(
                decrypted_password, rn, True)
            replaced_decrypted_password = _popChar(replaced_decrypted_password)
            bytes_uname = bytes(uname, encoding="utf-8")
            if decrypted_uname == bytes_uname:
                run = True
                decrypted_password_string = "{} : {}".format(
                    uname, replaced_decrypted_password)

            elif run == False:
                decrypted_password_string = "Username not found in the password list."

        return decrypted_password_string

    def _decrypt(self, filename, multiline=False):
        key = self.file_handler("rb", key=True).content
        # print(f"Key: {key}, type: {type(key)}")

        f = [i if i == filename else 0 for i in ["key", "content", "mp"]]
        x = f[f.index(filename)]

        if multiline == False:
            line = self.file_handler("rb", file=x).content
        else:
            lines = self.file_handler("rb", file=x, lines=True).content

        if multiline == False:
            # print(type(line), line)
            decrypted_line = Fernet(key).decrypt(line)
            return decrypted_line
        else:
            decrypted_lines = []
            for line in lines:
                decrypted_line = Fernet(key).decrypt(line)
                decrypted_lines.append(decrypted_line)
            return decrypted_lines

    def _checkUname(self, uname, pwd=None, r=False, p=False):
        rep = ['b"', "b'", "'", "\\n", '"']
        key_content = self.file_handler("rb", key=True).content

        phrases = self.file_handler("r", content=True, lines=True).content

        is_avilable = False

        for phrse in phrases:
            phrase = str(phrse)
            encrypted_uname, encrypted_password = phrase.split(":")
            # replaced_encrypted_uname = encrypted_uname.replace(
            # 'b"', '').replace("b'", "").replace("'", "")
            replaced_encrypted_uname = byteReplacer(
                encrypted_uname, rep, True)
            replaced_encrypted_password = byteReplacer(
                encrypted_password, rep, True)

            decrypted_uname = Fernet(key_content).decrypt(
                bytes(replaced_encrypted_uname, encoding="utf-8"))
            decrypted_password = Fernet(key_content).decrypt(
                bytes(replaced_encrypted_password, encoding="utf-8"))

            bytes_uname = bytes(uname, encoding="utf-8")
            if p == False:
                if bytes_uname == decrypted_uname:
                    is_avilable = True
                    line_number = phrases.index(phrse)

            elif bytes_uname == decrypted_uname:
                bytes_pwd = bytes(pwd, encoding="utf-8")
                if bytes_pwd == decrypted_password:
                    is_avilable = True
                    line_number = phrases.index(phrse)

        if is_avilable == True:
            if r == True:
                return line_number
            else:
                return 1

        else:
            return 0

    def _checkRecords(self):
        lines = self.file_handler("r", content=True, lines=True).content
        n_records = len(lines)

        return n_records
    
    def handleBackup(self):
        BackupHandler()

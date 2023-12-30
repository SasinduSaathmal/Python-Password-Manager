from base64 import urlsafe_b64encode, urlsafe_b64decode
from tools import byteReplacer, HandleFiles
import os


class BackupHandler():
    # Class for handle the backup feature.
    def __init__(self):
        self.content = None
        self.file_handler = HandleFiles

        self.flow()

    def flow(self):
        self.decide()

    def decide(self):
        # Ask the user to decide what to do.
        decision = input(
            "Do you want to create a backup or to \nimport a backup? (create/import): ").upper()
        if (decision == "C") or ("CREATE" in decision):
            self._createBackup()
            print("Backup successfully created at 'lib/pwm-backup.bak'.")
        elif (decision == "I") or ("IMPORT" in decision):
            user_decision = input(
                "Do you want to import the Encryption Key and the Master Password?\nThis will overwrite the existing files.(yes/no): ").upper()
            if (user_decision == "Y") or (user_decision == "YES"):
                n_passwords = self._importBackup(key_and_mp=True)
                print(
                    "Encryption key and the master password successfully imported.")
                print(f"{n_passwords} passwords successfully imported.")
            else:
                n_passwords = self._importBackup(key_and_mp=False)
                print(f"{n_passwords} passwords successfully imported.")
        print("Exited from backup.")

    def _createBackup(self):
        # Creating the backup, encrypting, and writing.
        replaced_list = []
        r = ["b'", "'", 'b"\'', "'\n\"", "b\"", "\\n\"", "[", "]", " "]
        content_list = self.file_handler(
            "rb", all=True, lines=True).content_list
        for item in content_list:
            # Replace unnecessary characters and make a proper backup.
            i = byteReplacer(item, r, True)
            replaced_list.append(i)

        # [KEY, Master Password, [p1, p2, p3]]
        # To remove the ',' in the passwords
        splitted = self._splitPwds(replaced_list)
        # We remove the passwords from the list: replaced_list and
        # Start to treat it seperately.
        replaced_list.pop()

        for y in splitted:
            # Then we add passwords one by one to the main list.
            replaced_list.append(y)
        self.content = replaced_list

        encoded_backup = self._encryptBackup()
        self.file_handler('BACKUP').writeBackup(encoded_backup)

    def _splitPwds(self, p_list):
        # To remove the ',' in the passwords
        splitted = list[str]
        for n, i in enumerate(p_list):
            if n == 2:
                i = str(i)
                splitted = i.split(",")

        return splitted

    def _encryptBackup(self):
        content = ""
        for i in self.content:
            content += f"\n{i}"
        bytes_content = bytes(content, encoding="utf-8")
        encoded = urlsafe_b64encode(bytes_content)

        return encoded

    def _importBackup(self, key_and_mp=False):
        # Import the backup from the backup file.
        encoded_backup = self._readBackup()
        decoded_backup = urlsafe_b64decode(encoded_backup)
        string_backup = str(decoded_backup, encoding="utf-8")
        list_backup = string_backup.split("\n")
        # We remove the first element of the list as it is just a '\n'
        list_backup.pop(0)
        for n, i in enumerate(list_backup):
            if n == 0:
                encryption_key = i
            if n == 1:
                master_password = i
        # After that we take the key and the mp out we remove them from the list.
        for _ in range(2):
            list_backup.pop(0)
        # Now we only have the passwords.

        # This line writes the backup.
        n_passwords = self._writeBackupToFiles(
            encryption_key, master_password, list_backup, key_and_mp)

        return n_passwords

    def _writeBackupToFiles(self, key, mp, passwords, key_and_mp=False):
        # Writes the backup.
        n_passwords = len(passwords)
        na_passwords = 0

        for password in passwords:
            avilable = self._checkAvilability(password)
            if avilable != True:
                self.file_handler("ab", content=True, body=password)
                na_passwords += 1
        if key_and_mp == True:
            self.file_handler("w", key=True, body=key)
            self.file_handler("w", mp=True, body=mp)

        return na_passwords

    def _checkAvilability(self, password_pharse: str):
        # To check whether the passwords already exist in the database.
        is_avilable = False
        r = ["b'", "'", 'b"\'', "'\n\"", "b\"", "\\n\"", "[", "]", " ", "\n"]
        phrases = self.file_handler("r", content=True, lines=True).content

        for phrase in phrases:
            # Check the passwords one by one.
            phrase = byteReplacer(phrase, r, True)
            if phrase == password_pharse:
                is_avilable = True
                return is_avilable

        return is_avilable

    def _readBackup(self):
        # In this case we are still importing the backup file from a default location.
        # It need to be fixed by adding a feature so the user can enter a location, and
        # the backup file will be imported from there.
        instance = self.file_handler('BACKUP')
        instance.readBackup()
        encoded_backup = instance.backup_content
        return encoded_backup

    # def _restoreBackup(self, key, mp, ps):
    #     self.file_handler("wb", key, )

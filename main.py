import sys
from manager import Manager

print("This is Password Manager")
help = ("""
Usage:
    add       - adds a password.
    remove    - removes a password.
    show      - show the stored passwords.
    master    - changes the context to master password.
    reset     - resets all the data in the program,
                including the encryption key, passwords and the master password.
    backup    - changes the context to backup.
    cls/clear - clears the screen.
    exit      - exits the program.
    help      - shows this help menu.
      """)

mgr = Manager()
print(help)


def main(mgr):
    running = True
    while ((usr_input := input("Password Manager> ").upper()) != "EXIT") \
          and (running == True):
        # usr_input = input("Password Manager> ")
        # print(f"({usr_input})")

        if (usr_input == "\n") or (usr_input == ""):
            print("HI")
            continue

        elif (usr_input.upper() == "QUIT") or (usr_input.upper() == "BYE"):
            break
            running = False

        elif usr_input.upper() == "HELP":
            print(help)
        else:
            mgr.status(usr_input)


try:
    main(mgr)
except KeyboardInterrupt:
    print()

print("Exiting...")
sys.exit()

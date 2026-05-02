import sys
import os
import getpass

# make sure we can import modules from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import elgamal
from modules import vault


def print_menu():
    print("\n--- Password Manager ---")
    print("1) Initialize new user")
    print("2) Add credential")
    print("3) Get credential")
    print("4) List all sites")
    print("5) Update credential")
    print("6) Delete credential")
    print("7) Exit")
    print("------------------------")


def ask_master_pw():
    pw = getpass.getpass("Master password: ")
    return pw


def ask_username():
    return input("Username: ").strip()


def main():
    print("Welcome to the Secure Password Manager")

    while True:
        print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            # --- init new user ---
            uname = ask_username()
            pw = getpass.getpass("Set master password: ")
            pw2 = getpass.getpass("Confirm master password: ")
            if pw != pw2:
                print("Passwords don't match, try again.")
                continue

            try:
                # generate elgamal keys first
                elgamal.initialize_user(uname)
                print(f"ElGamal keys generated for {uname}.")

                # then create the vault
                vault.create_vault(uname, pw)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "2":
            # --- add credential ---
            uname = ask_username()
            pw = ask_master_pw()
            site = input("Website: ").strip()
            site_user = input("Site username/email: ").strip()
            site_pw = getpass.getpass("Site password: ")

            try:
                vault.add_credential(uname, pw, site, site_user, site_pw)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            # --- get credential ---
            uname = ask_username()
            pw = ask_master_pw()
            site = input("Website to search: ").strip()

            try:
                result = vault.get_credential(uname, pw, site)
                if result:
                    print(f"\n  Website:  {result['website']}")
                    print(f"  Username: {result['username']}")
                    print(f"  Password: {result['password']}")
                else:
                    print(f"No credential found for '{site}'.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "4":
            # --- list all ---
            uname = ask_username()
            pw = ask_master_pw()

            try:
                sites = vault.list_credentials(uname, pw)
                if not sites:
                    print("Vault is empty.")
                else:
                    print("\nStored sites:")
                    for i, s in enumerate(sites, 1):
                        print(f"  {i}. {s}")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "5":
            # --- update credential ---
            uname = ask_username()
            pw = ask_master_pw()
            site = input("Website to update: ").strip()
            new_pw = getpass.getpass("New site password: ")

            try:
                vault.update_credential(uname, pw, site, new_pw)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "6":
            # --- delete credential ---
            uname = ask_username()
            pw = ask_master_pw()
            site = input("Website to delete: ").strip()

            confirm = input(f"Delete '{site}'? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Cancelled.")
                continue

            try:
                vault.delete_credential(uname, pw, site)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "7":
            print("Bye.")
            break

        else:
            print("Invalid option, pick 1-7.")


if __name__ == "__main__":
    main()

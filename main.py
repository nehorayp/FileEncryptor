import tkinter as tk
from tkinter import filedialog, font, messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = tk.Tk()
app.title("File Encryptor")
app.iconbitmap("Assets/encrypt-icon.ico")
app.geometry("500x300")
app.resizable(False, False)

KEY_FILE_PATH = ""


def show_decrypted_text(decrypted_text):
    """
    Function to create a new window and display decrypted text.

    Args:
        decrypted_text (str): The decrypted text to be displayed.
    """
    new_window = tk.Toplevel(app)
    new_window.title("Decrypted Text")

    text_widget = tk.Text(new_window, wrap="word", height=10, width=80)
    text_widget.pack(pady=10)
    text_widget.insert(tk.END, decrypted_text)


def create_aes_encryption():
    """
    Function to perform AES encryption on a selected file and save both the encrypted file and the encryption key.
    """
    file_path = filedialog.askopenfilename(title="Select a file for AES encryption")

    if file_path:
        aes_key = os.urandom(32)

        with open(file_path, 'rb') as file:
            plaintext = file.read()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Ask the user where to save the encrypted file
        encrypted_file_path = filedialog.asksaveasfilename(
            title="Save the encrypted file",
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc")]
        )

        if encrypted_file_path:
            with open(encrypted_file_path, 'wb') as file:
                file.write(ciphertext)

            # Ask the user where to save the key
            global KEY_FILE_PATH
            key_file_path = filedialog.asksaveasfilename(
                title="Save the encryption key",
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt")]
            )

            if key_file_path:
                with open(key_file_path, 'w') as key_file:
                    key_file.write(aes_key.hex())

                messagebox.showinfo("Encryption Complete", "AES Encryption has been completed. Key saved to: {}".format(key_file_path))
                KEY_FILE_PATH = key_file_path


def decrypt_aes_file():
    """
    Function to perform AES decryption on a selected file using a user-provided key and display the decrypted text.
    """
    file_path = filedialog.askopenfilename(title="Select a file for AES decryption")

    if file_path:
        while True:
            user_key = simpledialog.askstring("Key Input", "Enter the encryption key:")

            if user_key is None:
                # User canceled key entry
                return

            try:
                aes_key = bytes.fromhex(user_key)

                with open(file_path, 'rb') as file:
                    ciphertext = file.read()

                cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

                unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
                plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

                decoded_text = plaintext.decode('utf-8', errors='replace')

                show_decrypted_text(decoded_text)

                messagebox.showinfo("Decryption Complete", "AES Decryption has been completed.")
                break  # Break out of the loop if decryption is successful
            except ValueError:
                messagebox.showerror("Decryption Error", "Wrong key or invalid key format. Please enter a valid key")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")


def create_exit_button(main_window):
    """
    Function to create an Exit button in the main window.

    Args:
        main_window: The main window where the button will be placed.
    """
    exit_button = tk.Button(
        master=main_window,
        text="Exit",
        width=15,
        height=2,
        command=main_window.destroy  # Close the main window
    )
    exit_button.pack(side=tk.BOTTOM, pady=10)


def create_main_window():
    """
    Function to create the main window with buttons for AES encryption, AES decryption, and an Exit button.
    """
    main_window = tk.Toplevel(app)
    main_window.title("Main Menu")

    aes_button = tk.Button(
        master=main_window,
        text="AES Encryption",
        width=15,
        height=2,
        command=create_aes_encryption
    )
    aes_button.pack(side=tk.LEFT, padx=10)

    decrypt_aes_button = tk.Button(
        master=main_window,
        text="AES Decryption",
        width=15,
        height=2,
        command=decrypt_aes_file
    )
    decrypt_aes_button.pack(side=tk.LEFT, padx=10)

    create_exit_button(main_window)


def create_initial_window():
    """
    Function to create the initial window with a welcome message and a Continue button.
    """
    greet_frame = tk.Frame(app)
    greet_frame.pack(pady=50)
    description_frame = tk.Frame(app)
    description_frame.pack(pady=1)

    greet_font = font.Font(size=16, weight="bold", family="Arial")
    greet_label = tk.Label(
        master=greet_frame,
        text="Welcome to the File Encryptor Application",
        font=greet_font
    )
    greet_label.pack()

    description_font = font.Font(size=12, family="Arial")
    description_label = tk.Label(
        master=description_frame,
        text="Secure your files with AES Encryption.",
        font=description_font
    )
    description_label.pack()

    continue_frame = tk.Frame(app)
    continue_frame.pack(pady=30)

    continue_to_app = tk.Button(
        master=continue_frame,
        text="Continue",
        width=15,
        height=2,
        bg="purple",
        fg="white",
        font=("Arial", 14),
        command=lambda: [create_main_window(), app.withdraw()]
    )
    continue_to_app.pack()


create_initial_window()

app.mainloop()

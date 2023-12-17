import tkinter as tk
from tkinter import filedialog, font, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = tk.Tk()
app.title("File Encryptor")
app.iconbitmap("Assets/encrypt-icon.ico")
app.geometry("500x300")
app.resizable(False, False)


def show_decrypted_text(decrypted_text):
    # Function to create a new window and display decrypted text
    new_window = tk.Toplevel(app)
    new_window.title("Decrypted Text")

    text_widget = tk.Text(new_window, wrap="word", height=10, width=80)
    text_widget.pack(pady=10)
    text_widget.insert(tk.END, decrypted_text)


def create_aes_encryption():
    # Placeholder function for AES encryption
    file_path = filedialog.askopenfilename(title="Select a file for AES encryption")

    if file_path:
        aes_key = os.urandom(32)  # 256-bit key

        with open(file_path, 'rb') as file:
            plaintext = file.read()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted file
        encrypted_file_path = filedialog.asksaveasfilename(title="Save the encrypted file",
                                                            defaultextension=".enc",
                                                            filetypes=[("Encrypted Files", "*.enc")])
        if encrypted_file_path:
            with open(encrypted_file_path, 'wb') as file:
                file.write(ciphertext)

            messagebox.showinfo("Encryption Complete", "AES Encryption has been completed.")


def decrypt_aes_file():
    # Placeholder function for AES decryption
    file_path = filedialog.askopenfilename(title="Select a file for AES decryption")

    if file_path:
        aes_key = os.urandom(32)  # In a real-world scenario, you should securely manage and store the key

        with open(file_path, 'rb') as file:
            ciphertext = file.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Try to remove PKCS7 padding
        try:
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        except ValueError:
            # If ValueError occurs, it might be due to no padding being present
            plaintext = decrypted_data

        # Decode the plaintext, handling decoding errors
        try:
            decoded_text = plaintext.decode('utf-8', errors='replace')
        except UnicodeDecodeError as e:
            decoded_text = f"Decoding error: {e}"

        # Display the decrypted text in a new window
        show_decrypted_text(decoded_text)

        # Show a message indicating that decryption is complete
        messagebox.showinfo("Decryption Complete", "AES Decryption has been completed.")


def create_exit_button(main_window):
    exit_button = tk.Button(
        master=main_window,
        text="Exit",
        width=15,
        height=2,
        command=main_window.destroy  # Close the main window
    )
    exit_button.pack(side=tk.BOTTOM, pady=10)


def create_main_window():
    main_window = tk.Toplevel(app)
    main_window.title("Main Window")

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
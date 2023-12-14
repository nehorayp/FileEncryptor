import tkinter as tk

app = tk.Tk()
app.title("File Encryptor")
app.iconbitmap()

greet_label = tk.Label(text="Welcome to the File Encryptor application.")
greet_label.pack()

continue_to_app = tk.Button(
    text="Continue",
    width=15,
    height=2,
    bg="purple",
    fg="white"
)
continue_to_app.pack()
app.mainloop()

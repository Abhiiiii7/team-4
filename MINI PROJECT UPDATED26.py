import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

# Create the main application window
app = tk.Tk()
app.title("Encryption and Decryption with RSA")

# Generate an RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Function to load a text file and display its content
def load_file():
    file_path = filedialog.askopenfilename(title="Select a Text File")
    if file_path:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                file_contents = file.read()
            input_text.delete("1.0", "end")
            input_text.insert("1.0", file_contents)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load the file: {str(e)}")

# Function to encrypt a message with RSA
def encrypt_text():
    message = input_text.get("1.0", "end-1c")
    if message:
        message_bytes = message.encode('utf-8')
        public_key = private_key.public_key()
        encrypted_message = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_message_base64)
    else:
        messagebox.showerror("Error", "Please enter a message to encrypt.")

# Function to decrypt a message with RSA
def decrypt_text():
    encrypted_message_base64 = input_text.get("1.0", "end-1c")
    if encrypted_message_base64:
        try:
            encrypted_message = base64.b64decode(encrypted_message_base64.encode('utf-8'))
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            output_text.delete("1.0", "end")
            output_text.insert("1.0", decrypted_message.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Invalid input or key.")
    else:
        messagebox.showerror("Error", "Please enter an encrypted message to decrypt.")

# Function to reset the input and output fields
def reset_fields():
    input_text.delete("1.0", "end")
    output_text.delete("1.0", "end")

# Create GUI components with specified button colors
load_file_button = tk.Button(app, text="Load File", command=load_file, bg="yellow")
encrypt_button = tk.Button(app, text="Encrypt", command=encrypt_text, bg="green")
decrypt_button = tk.Button(app, text="Decrypt", command=decrypt_text, bg="red")
reset_button = tk.Button(app, text="Reset", command=reset_fields, bg="blue")
input_text = tk.Text(app, height=5, width=40)
output_text = tk.Text(app, height=5, width=40)

# Arrange GUI components
load_file_button.pack()
input_text.pack()
encrypt_button.pack()
decrypt_button.pack()
output_text.pack()
reset_button.pack()

# Start the main event loop
app.mainloop()
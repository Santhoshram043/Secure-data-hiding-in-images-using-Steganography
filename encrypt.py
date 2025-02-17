import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encode_image(img, secret_message, password):
    if len(secret_message) == 0:
        raise ValueError("Secret message is empty")
    
    binary_secret_msg = ''.join(format(ord(i), '08b') for i in secret_message)
    binary_secret_msg += '1111111111111110'  
    
    hashed_password = hash_password(password)
    binary_secret_msg = ''.join(format(ord(i), '08b') for i in hashed_password) + binary_secret_msg

    if len(binary_secret_msg) > img.size[0] * img.size[1] * 3:
        raise ValueError("Image is too small to hold the secret message")
    
    pixels = img.load()
    data_index = 0
    
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            pixel = list(pixels[i, j])

            for k in range(3):  
                if data_index < len(binary_secret_msg):
                    pixel[k] = pixel[k] & ~1 | int(binary_secret_msg[data_index])
                    data_index += 1

            pixels[i, j] = tuple(pixel)

            if data_index >= len(binary_secret_msg):
                return img

def open_encrypt_window():
    encrypt_window = tk.Toplevel(root)
    encrypt_window.title("Encrypt Message")
    encrypt_window.geometry("400x250")
    
    def encrypt():
        image_path = filedialog.askopenfilename(title="Select Image to Encrypt")
        if not image_path:
            return

        secret_message = entry_message.get()
        password = entry_password.get()
        
        if not secret_message or not password:
            messagebox.showerror("Error", "Please enter both a secret message and a password")
            return

        try:
            img = Image.open(image_path)
            img = img.convert('RGB')
            encoded_img = encode_image(img, secret_message, password)
            encoded_img.save("encoded_image.png")
            messagebox.showinfo("Success", "Image encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    label_message = tk.Label(encrypt_window, text="Secret Message:")
    label_message.pack(pady=5)
    
    entry_message = tk.Entry(encrypt_window, width=40)
    entry_message.pack(pady=5)
    
    label_password = tk.Label(encrypt_window, text="Password:")
    label_password.pack(pady=5)
    
    entry_password = tk.Entry(encrypt_window, width=40, show="*")
    entry_password.pack(pady=5)
    
    button_encrypt = tk.Button(encrypt_window, text="Select Image & Encrypt", command=encrypt)
    button_encrypt.pack(pady=10)

root = tk.Tk()
root.title("Steganography Tool - Encrypt")
root.geometry("300x150")

button_encrypt_main = tk.Button(root, text="Encrypt", command=open_encrypt_window, width=20, height=2, font=("Arial", 10, "bold"))
button_encrypt_main.pack(pady=10, anchor="center")
root.mainloop()

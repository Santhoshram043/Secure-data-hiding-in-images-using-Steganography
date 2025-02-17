import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def decode_image(img, password):
    pixels = img.load()
    binary_secret_msg = ""

    for i in range(img.size[0]):
        for j in range(img.size[1]):
            pixel = pixels[i, j]

            for k in range(3):  
                binary_secret_msg += str(pixel[k] & 1)

                if len(binary_secret_msg) >= 16 and binary_secret_msg[-16:] == '1111111111111110':
                    binary_secret_msg = binary_secret_msg[:-16] 
                    secret_message = ""

                    for l in range(0, len(binary_secret_msg), 8):
                        byte = binary_secret_msg[l:l+8]
                        if len(byte) == 8:  
                            secret_message += chr(int(byte, 2))
                    
                    stored_hashed_password = secret_message[:64]
                    actual_message = secret_message[64:]
                    
                    if stored_hashed_password == hash_password(password):
                        return actual_message
                    else:
                        raise ValueError("Incorrect password")
    return ""

def open_decrypt_window():
    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("Decrypt Message")
    decrypt_window.geometry("400x250")
    
    def decrypt():
        image_path = filedialog.askopenfilename(title="Select Image to Decrypt")
        if not image_path:
            return
        
        password = entry_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter the password")
            return
        
        try:
            img = Image.open(image_path)
            img = img.convert('RGB')
            secret_message = decode_image(img, password)
            messagebox.showinfo("Decrypted Message", f"The secret message is: {secret_message}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    label_password = tk.Label(decrypt_window, text="Password:")
    label_password.pack(pady=5)
    
    entry_password = tk.Entry(decrypt_window, width=40, show="*")
    entry_password.pack(pady=5)
    
    button_decrypt = tk.Button(decrypt_window, text="Select Image & Decrypt", command=decrypt)
    button_decrypt.pack(pady=10)

root = tk.Tk()
root.title("Steganography Tool - Decrypt")
root.geometry("300x150")

button_decrypt_main = tk.Button(root, text="Decrypt", command=open_decrypt_window, width=20, height=2, font=("Arial", 10, "bold"))
button_decrypt_main.pack(pady=10, anchor="center")
root.mainloop()

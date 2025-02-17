Steganography Tool – Hide & Retrieve Secret Messages in Images
Title: "PixelVault-Image-Based-Encryption-Tool"

Overview:
This is a Python-based Steganography Tool that allows users to hide secret messages inside images securely using LSB (Least Significant Bit) steganography. The tool also provides password protection to ensure only authorized users can retrieve the hidden message.

Features:
- User-Friendly GUI – Simple and interactive Tkinter interface  
- Password-Protected Encryption & Decryption – Added security layer  
- Hidden Communication – Messages are embedded invisibly in images  
- No Image Quality Loss – Image remains visually unchanged  
- Supports Various Image Formats – Works with PNG and other image types  

Technologies Used:
- Python (Main Programming Language)  
- Tkinter (GUI Development)  
- PIL (Pillow) (Image Processing)  
- Hashlib (Password Security)  

Installation & Usage:
1. Installation:
Make sure you have Python 3.x installed. Then, install the required dependencies:
"pip install pillow"

2. Running the Tool:
Run the Python script using:
"python steganography_tool.py"

3. How to Use?
- Encryption:
1. Click Encrypt → Select an Image  
2. Enter your Secret Message & Password  
3. The encoded image will be saved as `encoded_image.png`  

- Decryption:
1. Click Decrypt → Select the Encoded Image  
2. Enter the Correct Password  
3. The hidden message is revealed!  

Security Note
This tool uses LSB steganography with a SHA-256 password hash for basic security. However, it's not a substitute for strong encryption methods when dealing with highly sensitive data.  

Future Enhancements
- Mobile App Version  
- Support for More Image Formats 
- Stronger Encryption Algorithms  
- Cloud-Based Secure Steganography  

Contributing
Feel free to fork this project and submit pull requests for improvements!  

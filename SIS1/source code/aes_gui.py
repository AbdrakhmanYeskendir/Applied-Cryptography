
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import base64
import os

# Try to import our AES modules
try:
    from aes_core import generate_key, bytes_to_hex, hex_to_bytes
    from aes_modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
    from aes_modes import ctr_encrypt, ctr_decrypt, gcm_encrypt, gcm_decrypt
    AES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: AES modules not available: {e}")
    AES_AVAILABLE = False
    # Dummy functions for testing
    def generate_key(size): return b"0"*(size//8)
    def bytes_to_hex(b): return b.hex()
    def hex_to_bytes(h): return bytes.fromhex(h) if h else b""

class SimpleAESApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AES Tool - Student Project")
        self.root.geometry("700x600")
        
        # Variables
        self.key_size = tk.IntVar(value=128)
        self.mode = tk.StringVar(value="ECB")
        self.key_text = tk.StringVar()
        self.input_text = tk.StringVar()
        self.output_text = tk.StringVar()
        
        self.setup_ui()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        ttk.Label(main_frame, text="AES Encryption Tool", 
                 font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
        settings_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Key size selection
        ttk.Label(settings_frame, text="Key Size:").grid(row=0, column=0, padx=5)
        ttk.Radiobutton(settings_frame, text="128-bit", variable=self.key_size, value=128).grid(row=0, column=1, padx=5)
        ttk.Radiobutton(settings_frame, text="192-bit", variable=self.key_size, value=192).grid(row=0, column=2, padx=5)
        ttk.Radiobutton(settings_frame, text="256-bit", variable=self.key_size, value=256).grid(row=0, column=3, padx=5)
        
        # Mode selection
        ttk.Label(settings_frame, text="Mode:").grid(row=1, column=0, padx=5, pady=5)
        modes = ["ECB", "CBC", "CTR", "GCM"]
        for i, mode in enumerate(modes):
            ttk.Radiobutton(settings_frame, text=mode, variable=self.mode, value=mode).grid(row=1, column=i+1, padx=5)
        
        # Key input
        ttk.Label(settings_frame, text="Key (hex):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        key_entry = ttk.Entry(settings_frame, textvariable=self.key_text, width=50)
        key_entry.grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(settings_frame, text="Generate", command=self.generate_key).grid(row=2, column=4, padx=5)
        
        # Input/Output area
        io_frame = ttk.Frame(main_frame)
        io_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input
        ttk.Label(io_frame, text="Input Text:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_area = scrolledtext.ScrolledText(io_frame, width=40, height=8)
        self.input_area.grid(row=1, column=0, padx=5, pady=5)
        
        # Buttons in middle
        btn_frame = ttk.Frame(io_frame)
        btn_frame.grid(row=1, column=1, padx=20)
        
        ttk.Button(btn_frame, text="Encrypt →", command=self.encrypt).pack(pady=5)
        ttk.Button(btn_frame, text="← Decrypt", command=self.decrypt).pack(pady=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear).pack(pady=5)
        ttk.Button(btn_frame, text="Test", command=self.run_test).pack(pady=20)
        
        # Output
        ttk.Label(io_frame, text="Output Text:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.output_area = scrolledtext.ScrolledText(io_frame, width=40, height=8)
        self.output_area.grid(row=1, column=2, padx=5, pady=5)
        
        # File operations
        file_frame = ttk.LabelFrame(main_frame, text="File Operations", padding="10")
        file_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(file_frame, text="Encrypt File...", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Decrypt File...", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Show ECB Weakness", command=self.show_ecb_weakness).pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status, relief=tk.SUNKEN).grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
    
    def generate_key(self):
        """Generate random key"""
        try:
            key_size = self.key_size.get()
            key = generate_key(key_size)
            self.key_text.set(key.hex())
            self.status.set(f"Generated {key_size}-bit key")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {e}")
    
    def get_key_bytes(self):
        """Convert hex key to bytes"""
        key_hex = self.key_text.get().strip()
        if not key_hex:
            messagebox.showerror("Error", "Please enter or generate a key")
            return None
        
        try:
            # Remove spaces and colons if present
            key_hex = key_hex.replace(" ", "").replace(":", "")
            return bytes.fromhex(key_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid hex key format")
            return None
    
    def encrypt(self):
        """Encrypt input text"""
        if not AES_AVAILABLE:
            messagebox.showerror("Error", "AES modules not loaded")
            return
        
        key = self.get_key_bytes()
        if not key:
            return
        
        plaintext = self.input_area.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "No input text to encrypt")
            return
        
        try:
            # Check if input is hex
            try:
                data = bytes.fromhex(plaintext)
            except ValueError:
                data = plaintext.encode('utf-8')
            
            mode = self.mode.get()
            key_size = self.key_size.get()
            
            if mode == "ECB":
                result = ecb_encrypt(data, key, key_size)
            elif mode == "CBC":
                result = cbc_encrypt(data, key, key_size)
            elif mode == "CTR":
                result = ctr_encrypt(data, key, key_size)
            elif mode == "GCM":
                result = gcm_encrypt(data, key, key_size)
            else:
                messagebox.showerror("Error", f"Unknown mode: {mode}")
                return
            
            # Show as hex
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert("1.0", result.hex())
            self.status.set(f"Encrypted using {mode} mode")
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt(self):
        """Decrypt input text"""
        if not AES_AVAILABLE:
            messagebox.showerror("Error", "AES modules not loaded")
            return
        
        key = self.get_key_bytes()
        if not key:
            return
        
        ciphertext = self.input_area.get("1.0", tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("Warning", "No input text to decrypt")
            return
        
        try:
            # Try to parse as hex
            try:
                data = bytes.fromhex(ciphertext)
            except ValueError:
                # Try base64
                try:
                    data = base64.b64decode(ciphertext)
                except:
                    messagebox.showerror("Error", "Input must be hex or base64")
                    return
            
            mode = self.mode.get()
            key_size = self.key_size.get()
            
            if mode == "ECB":
                result = ecb_decrypt(data, key, key_size)
            elif mode == "CBC":
                result = cbc_decrypt(data, key, key_size)
            elif mode == "CTR":
                result = ctr_decrypt(data, key, key_size)
            elif mode == "GCM":
                result = gcm_decrypt(data, key, key_size)
            else:
                messagebox.showerror("Error", f"Unknown mode: {mode}")
                return
            
            # Try to decode as text, otherwise show hex
            try:
                output = result.decode('utf-8')
            except UnicodeDecodeError:
                output = result.hex()
            
            self.output_area.delete("1.0", tk.END)
            self.output_area.insert("1.0", output)
            self.status.set(f"Decrypted using {mode} mode")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
    
    def clear(self):
        """Clear all fields"""
        self.input_area.delete("1.0", tk.END)
        self.output_area.delete("1.0", tk.END)
        self.status.set("Cleared")
    
    def run_test(self):
        """Run simple test"""
        # Simple test to verify basic functionality
        test_key = b"1234567890123456"
        test_text = b"Hello AES!"
        
        self.key_text.set(test_key.hex())
        self.input_area.delete("1.0", tk.END)
        self.input_area.insert("1.0", test_text.decode('utf-8'))
        
        self.encrypt()
        self.status.set("Test completed - check encryption works")
    
    def encrypt_file(self):
        """Encrypt a file"""
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if not filename:
            return
        
        key = self.get_key_bytes()
        if not key:
            return
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            mode = self.mode.get()
            key_size = self.key_size.get()
            
            if mode == "ECB":
                encrypted = ecb_encrypt(data, key, key_size)
            elif mode == "CBC":
                encrypted = cbc_encrypt(data, key, key_size)
            elif mode == "CTR":
                encrypted = ctr_encrypt(data, key, key_size)
            elif mode == "GCM":
                encrypted = gcm_encrypt(data, key, key_size)
            else:
                messagebox.showerror("Error", f"Unknown mode: {mode}")
                return
            
            save_name = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if save_name:
                with open(save_name, 'wb') as f:
                    f.write(encrypted)
                self.status.set(f"File encrypted and saved as {save_name}")
                
        except Exception as e:
            messagebox.showerror("File Error", str(e))
    
    def decrypt_file(self):
        """Decrypt a file"""
        filename = filedialog.askopenfilename(title="Select file to decrypt")
        if not filename:
            return
        
        key = self.get_key_bytes()
        if not key:
            return
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            mode = self.mode.get()
            key_size = self.key_size.get()
            
            if mode == "ECB":
                decrypted = ecb_decrypt(data, key, key_size)
            elif mode == "CBC":
                decrypted = cbc_decrypt(data, key, key_size)
            elif mode == "CTR":
                decrypted = ctr_decrypt(data, key, key_size)
            elif mode == "GCM":
                decrypted = gcm_decrypt(data, key, key_size)
            else:
                messagebox.showerror("Error", f"Unknown mode: {mode}")
                return
            
            save_name = filedialog.asksaveasfilename(
                title="Save decrypted file",
                defaultextension=".dec",
                filetypes=[("All files", "*.*")]
            )
            
            if save_name:
                with open(save_name, 'wb') as f:
                    f.write(decrypted)
                self.status.set(f"File decrypted and saved as {save_name}")
                
        except Exception as e:
            messagebox.showerror("File Error", str(e))
    
    def show_ecb_weakness(self):
        """Show ECB mode weakness"""
        messagebox.showinfo("ECB Weakness", 
            "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks.\n\n"
            "This reveals patterns in the data. For example:\n"
            "1. Encrypt an image with visible patterns\n"
            "2. Patterns remain visible in encrypted image!\n"
            "3. CBC/CTR/GCM don't have this problem.\n\n"
            "Try encrypting a file with repeating data to see the effect."
        )

def main():
    app = SimpleAESApp()
    app.root.mainloop()

if __name__ == "__main__":
    main()
import tkinter
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

#font
FONT=("Verdana",12,"normal")

secret_window=tkinter.Tk()
secret_window.title("Secret Notes")
secret_window.config(padx=30,pady=30)
secret_window.minsize(width=400,height=500)


# Anahtar oluşturma (master key kullanılarak)
def generate_key(master_key):
    # Master key'i hashleyip, 32 byte uzunluğunda bir değer elde ediyoruz
    digest = hashlib.sha256(master_key).digest()
    return base64.urlsafe_b64encode(digest)


# Şifreleme fonksiyonu
def encrypt_message():
    title = entry_title.get()
    message = entry_text.get("1.0", tkinter.END).strip()
    master_key = entry_key.get().strip()

    if not title or not message or not master_key:
        messagebox.showwarning("Uyarı", "Tüm alanları doldurun.")
        return

    # Master key'den bir Fernet key oluştur
    key = generate_key(master_key.encode())
    fernet = Fernet(key)

    try:
        encrypted_message = fernet.encrypt(message.encode())
        with open(f"{title}.txt", "wb") as file:
            file.write(encrypted_message)
        messagebox.showinfo("Başarılı", f"Şifrelenmiş mesaj {title}.txt dosyasına kaydedildi.")
        entry_text.delete("1.0", tkinter.END)
    except Exception as e:
        messagebox.showerror("Hata", f"Şifreleme işlemi başarısız oldu: {e}")


# Şifre çözme fonksiyonu
def decrypt_message():
    title = entry_title.get()
    master_key = entry_key.get().strip()

    if not title or not master_key:
        messagebox.showwarning("Uyarı", "Lütfen başlık ve master key'i girin.")
        return

    try:
        with open(f"{title}.txt", "rb") as file:
            encrypted_message = file.read()

        # Master key'den bir Fernet key oluştur
        key = generate_key(master_key.encode())
        fernet = Fernet(key)

        decrypted_message = fernet.decrypt(encrypted_message).decode()
        entry_text.delete("1.0", tkinter.END)
        entry_text.insert(tkinter.END, decrypted_message)
        messagebox.showinfo("Başarılı", f"{title}.txt dosyasından şifre çözme işlemi tamamlandı.")
    except Exception as e:
        messagebox.showerror("Hata", f"Şifre çözme işlemi başarısız oldu: {e}")

#image file
image=tkinter.PhotoImage(file="topsecret.png")

#image label
image_label=tkinter.Label(image=image)
image_label.pack()

#title label
label_title=tkinter.Label(text="Enter your title",pady=5,font=FONT)
label_title.pack()
#title entry
entry_title=tkinter.Entry(width=27)
entry_title.pack()

#secret label
secret=tkinter.Label(text="Enter your secret",pady=5,font=FONT)
secret.pack()
#secret textbox
entry_text=tkinter.Text(width=20,height=10)
entry_text.pack()

#master key label
master=tkinter.Label(text="Enter master key",pady=5,font=FONT)
master.pack()
#master key entry
entry_key=tkinter.Entry(width=27)
entry_key.pack()

#save button
encrypt_button=tkinter.Button(text="Save & Encrypt",pady=5,command=encrypt_message)
encrypt_button.pack()

#decrypt button
decrypt_button=tkinter.Button(text="Decrypt",pady=5, command=decrypt_message)
decrypt_button.pack()

secret_window.mainloop()
#mcdouglasx
#easy_wallet_backup.py
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import xprv
import addr

def load_file():
    global file_path
    file_path = filedialog.askopenfilename(filetypes=[("Wallet files", "*.dat"), ("All files", "*.*")])
    if file_path:
        file_label.config(text=f"Selected file: {file_path}")
    else:
        file_label.config(text="No file selected")

def process_file(option):
    xpriv_label.pack_forget()
    xpriv_entry.pack_forget()
    num_addresses_label.pack_forget()
    num_addresses_entry.pack_forget()
    go_button.pack_forget()
    
    if option == "Extended privkey":
        xpriv_label.pack(side=tk.TOP, pady=5, before=result_textbox)
        xpriv_entry.pack(side=tk.TOP, pady=5, before=result_textbox)
        num_addresses_label.pack(side=tk.TOP, pady=5, before=result_textbox)
        num_addresses_entry.pack(side=tk.TOP, pady=5, before=result_textbox)
        go_button.config(command=process_extended_privkey)
        go_button.pack(side=tk.TOP, pady=5, before=result_textbox)
        
    elif option == "Extract Addresses":
        if file_label.cget("text") == "No file selected":
            messagebox.showwarning("Warning", "Please load a wallet file first.")
            return
        wallet_file = file_label.cget("text").replace("Selected file: ", "")
        try:
            addresses = addr.extract_addrs(wallet_file)
            result_text = f"Valid addresses found ({len(addresses)}):\n" + "\n".join(addresses)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract addresses: {e}")
            return
        result_textbox.config(state=tk.NORMAL)
        result_textbox.delete(1.0, tk.END)
        result_textbox.insert(tk.END, result_text)
        result_textbox.config(state=tk.DISABLED)
        
    elif option == "Dump Descriptor":
        xpriv_label.pack(side=tk.TOP, pady=5, before=result_textbox)
        xpriv_entry.pack(side=tk.TOP, pady=5, before=result_textbox)
        go_button.config(command=process_dump_descriptor)
        go_button.pack(side=tk.TOP, pady=5, before=result_textbox)
    else:
        messagebox.showerror("Error", "Invalid option.")

def process_extended_privkey():
    try:
        xpriv_val = xpriv_entry.get().strip()
        drv = int(num_addresses_entry.get())
        result_text = xprv.derive_addrs(xpriv_val, drv)
        result_textbox.config(state=tk.NORMAL)
        result_textbox.delete(1.0, tk.END)
        result_textbox.insert(tk.END, result_text)
        result_textbox.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def process_dump_descriptor():
    if file_label.cget("text") == "No file selected":
        messagebox.showwarning("Warning", "Please load a wallet file first.")
        return
    try:
        wallet_file = file_label.cget("text").replace("Selected file: ", "")
        xpriv_val = xpriv_entry.get().strip()
        result_text = xprv.dump_descriptor(xpriv_val, wallet_file)
        result_textbox.config(state=tk.NORMAL)
        result_textbox.delete(1.0, tk.END)
        result_textbox.insert(tk.END, result_text)
        result_textbox.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"Dump Descriptor failed: {e}")

def process_export2electrum():
    current_option = options_var.get()
    xpriv_val = xpriv_entry.get().strip()
    if xpriv_val == "":
        messagebox.showwarning("Warning", "Please enter the Extended Privkey (xpriv) for export.")
        return
    if current_option == "Dump Descriptor":
        if file_label.cget("text") == "No file selected":
            messagebox.showwarning("Warning", "Please load a wallet file for export.")
            return
        wallet_file_val = file_label.cget("text").replace("Selected file: ", "")
        try:
            result_text = xprv.export_to_electrum(xpriv_val, wallet_file_val)
        except Exception as e:
            messagebox.showerror("Error", f"Export to Electrum failed: {e}")
            return
    elif current_option == "Extended privkey":
        try:
            drv = int(num_addresses_entry.get())
        except Exception:
            messagebox.showerror("Error", "Enter a valid number of addresses for export.")
            return
        try:
            result_text = xprv.export_to_electrum(xpriv_val, "", drv)
        except Exception as e:
            messagebox.showerror("Error", f"Export to Electrum failed: {e}")
            return
    else:
        messagebox.showwarning("Warning", "Export to Electrum is only available for Dump Descriptor or Extended privkey modes.")
        return

    result_textbox.config(state=tk.NORMAL)
    result_textbox.delete(1.0, tk.END)
    result_textbox.insert(tk.END, result_text)
    result_textbox.config(state=tk.DISABLED)

def save_result():
    result_text = result_textbox.get(1.0, tk.END)
    if result_text.strip() == "":
        messagebox.showwarning("Warning", "No result to save.")
        return
    file_save = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_save:
        with open(file_save, "w") as file:
            file.write(result_text)
        messagebox.showinfo("Save", f"Result saved to {file_save}")

def enable_copy(event):
    event.widget.config(state=tk.NORMAL)

def disable_copy(event):
    event.widget.config(state=tk.DISABLED)

def show_donation_info():
    donation_window = tk.Toplevel(root)
    donation_window.title("Donate")
    donation_window.configure(bg="#FF9900")
    
    image_path = "qrcode.png"
    try:
        donation_image = tk.PhotoImage(file=image_path)
        image_label = ttk.Label(donation_window, image=donation_image)
        image_label.image = donation_image
        image_label.pack(pady=5)
    except tk.TclError:
        messagebox.showerror("Error", "QR Code image not found.")
    
    global address_textbox
    address_textbox = tk.Text(donation_window, height=1, bg="#FF9900", fg="black", bd=0)
    address_textbox.insert(tk.END, "bitcoin address: bc1qxs47ttydl8tmdv8vtygp7dy76lvayz3r6rdahu")
    address_textbox.config(state=tk.DISABLED)
    address_textbox.tag_configure("center", justify="center")
    address_textbox.tag_add("center", 1.0, "end")
    address_textbox.pack(pady=5)
    
    right_click_menu = tk.Menu(address_textbox, tearoff=0)
    right_click_menu.add_command(label="Copy", command=lambda: address_textbox.event_generate("<<Copy>>"))
    
    def show_right_click_menu(event):
        right_click_menu.tk_popup(event.x_root, event.y_root)
    
    address_textbox.bind("<Button-3>", show_right_click_menu)

root = tk.Tk()
root.title("Easy Wallet Backup")
root.geometry("800x700")
root.configure(bg="#FF9900")

style = ttk.Style()
style.configure("TLabel", background="#FF9900", foreground="black")
style.configure("TButton", padding=6)

file_label = ttk.Label(root, text="No file selected")
file_label.pack(pady=10)

load_button = ttk.Button(root, text="Load File", command=load_file)
load_button.pack(pady=10)

options_label = ttk.Label(root, text="OPTIONS:")
options_label.pack(pady=5)

options = ["Dump Descriptor", "Extended privkey", "Extract Addresses"]
options_var = tk.StringVar()
options_combobox = ttk.Combobox(root, textvariable=options_var, values=options)
options_combobox.pack(pady=10)
options_combobox.bind("<<ComboboxSelected>>", lambda event: process_file(options_combobox.get()))

result_textbox = tk.Text(root, height=12, width=60, state=tk.NORMAL, bg="black", fg="white")
result_textbox.pack(pady=10, expand=True, fill=tk.BOTH)

result_text_menu = tk.Menu(result_textbox, tearoff=0)
result_text_menu.add_command(label="Copy", command=lambda: root.focus_get().event_generate("<<Copy>>"))

def show_result_text_menu(event):
    try:
        result_text_menu.tk_popup(event.x_root, event.y_root)
    finally:
        result_text_menu.grab_release()

result_textbox.bind("<Button-3>", show_result_text_menu)

xpriv_label = ttk.Label(root, text="Extended Privkey (xpriv):")
xpriv_entry = ttk.Entry(root, width=60)
num_addresses_label = ttk.Label(root, text="Number of Addresses to Generate:")
num_addresses_entry = ttk.Entry(root, width=10)
go_button = ttk.Button(root, text="Go")

xpriv_menu = tk.Menu(xpriv_entry, tearoff=0)
xpriv_menu.add_command(label="Cut", command=lambda: xpriv_entry.event_generate("<<Cut>>"))
xpriv_menu.add_command(label="Copy", command=lambda: xpriv_entry.event_generate("<<Copy>>"))
xpriv_menu.add_command(label="Paste", command=lambda: xpriv_entry.event_generate("<<Paste>>"))
xpriv_entry.bind("<Button-3>", lambda event: xpriv_menu.tk_popup(event.x_root, event.y_root))

num_menu = tk.Menu(num_addresses_entry, tearoff=0)
num_menu.add_command(label="Cut", command=lambda: num_addresses_entry.event_generate("<<Cut>>"))
num_menu.add_command(label="Copy", command=lambda: num_addresses_entry.event_generate("<<Copy>>"))
num_menu.add_command(label="Paste", command=lambda: num_addresses_entry.event_generate("<<Paste>>"))
num_addresses_entry.bind("<Button-3>", lambda event: num_menu.tk_popup(event.x_root, event.y_root))

xpriv_label.pack_forget()
xpriv_entry.pack_forget()
num_addresses_label.pack_forget()
num_addresses_entry.pack_forget()
go_button.pack_forget()

button_frame = tk.Frame(root, bg="#FF9900")
button_frame.pack(pady=10)
save_button = ttk.Button(button_frame, text="Save Result", command=save_result)
save_button.pack(side=tk.LEFT, padx=10)
export_button = ttk.Button(button_frame, text="Export2Electrum", command=process_export2electrum)
export_button.pack(side=tk.LEFT, padx=10)

donate_button = ttk.Button(root, text="Donate", command=show_donation_info)
donate_button.pack(pady=10, side=tk.BOTTOM, anchor=tk.SE)

root.columnconfigure(0, weight=1)
root.rowconfigure(3, weight=1)

root.mainloop()

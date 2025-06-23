import ctypes
import tkinter as tk
from tkinter import messagebox

def ask_user_choice(title, message):
    root = tk.Tk()
    root.withdraw()
    result = messagebox.askyesno(title, message + "\n\nYes = Continue, No = Stop")
    root.destroy()
    return "Continue" if result else "Stop"


def show_popup(title: str, message: str):
    # MB_SYSTEMMODAL = 0x1000, MB_OK = 0x0
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x00001000)

# This is a sample Python script.

# Press Shift+F6 to execute it or replace it with your code.
"""
import phoneScan
import FileScan
import sys
phoneScan.get_phone_number()
FileScan.get_file_scan()

"""
# Below are code for the GUI
import sys
import ctypes
import tkinter as tk
from tkinter import filedialog
from tkinter import *
import MalShare
from MalShare import get_malshare_info

#Makes GUI less blurry
#if 'win' in sys.platform:
#    ctypes.windll.shcore.SetProcessDpiAwareness(1)

main = Tk() #Tkinter window

#Window styles
main.geometry("600x600") #window size
main.title("Global Search") #Title of window 

#sets logo at top bar
logo = PhotoImage(file='logo.png')
main.iconphoto(True,logo)
main.config(background="#4A4459") #background color


#Text for instructions
home = Label(main,
             text="Pick a service:", 
             font=('Courier New',12), 
             fg="white", 
             bg="#4A4459", 
             padx=10,
             pady=10)
home.pack()

#Functions for each API Windows
"""
Create functions for every buttons
"""
def create_window(button):
    title_text = button.cget("text")
    
    new_window = Tk()
    new_window.title(title_text)
    new_window.geometry("400x400")
    
    main.destroy()  #closes main window

#MalShare window function
def malShare_window():
    new_window = tk.Toplevel(main)
    new_window.title("MalShare")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")

    def compute_sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    #Function to open file 
    def openFile():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        print("Selected:", filepath)
        hash_value = compute_sha256(filepath)
        print("File hash:", hash_value)
        # Correct call
        get_malshare_info(file_hash=hash_value, save_path="malshare_result.json")
    #Button
    tk.Button(new_window, 
              text="Select a File", 
              command=openFile,
              font=('Courier New', 12), 
              bg="#00C3EB", 
              fg="black", 
              activebackground='#FF0000', 
              activeforeground='white',
              width=20).pack(pady=20)
    main.withdraw()  #closes main window

#URLScan Window Function
def urlScan_window():
    new_window = tk.Toplevel(main)
    new_window.title("URLScan")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")
    #Text in the Window
    tk.Label(new_window,
             text="Paste a url:", 
             font=('Courier New',12), 
             fg="white", 
             bg="#4A4459", 
             padx=10,
             pady=10).pack()
    #Text box for url
    entry = Entry(new_window, font=('Courier New', 12))
    entry.pack(pady=20)
    #Submit Button
    def on_submit():
        return
    submit_button = Button(new_window, 
                           text="Submit", 
                           command=on_submit,
                           font=('Courier New', 12), 
                           bg="#00C3EB", 
                           fg="black", 
                           activebackground='#FF0000', 
                           activeforeground='white',
                           width=20)
    submit_button.pack()
    main.withdraw()  #closes main window

#WebOfTrust Function
def webOfTrust_window():
    new_window = tk.Toplevel(main)
    new_window.title("Web of Trust")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")
    #Text in the Window
    tk.Label(new_window,
             text="URL or IP address", 
             font=('Courier New',12), 
             fg="white", 
             bg="#4A4459", 
             padx=10,
             pady=10).pack()
    #Text box for url
    entry = Entry(new_window, font=('Courier New', 12))
    entry.pack(pady=20)
    #Submit Button
    def on_submit():
        return
    submit_button = Button(new_window, 
                           text="Submit", 
                           command=on_submit,
                           font=('Courier New', 12), 
                           bg="#00C3EB", 
                           fg="black", 
                           activebackground='#FF0000', 
                           activeforeground='white',
                           width=20)
    submit_button.pack()
    main.withdraw()  #closes main window

#VeriPhone Function
def veriPhone():
    new_window = tk.Toplevel(main)
    new_window.title("VeriPhone")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")
    #Text
    phone_label = tk.Label(new_window, 
                           text="Phone Number:",
                           font=('Courier New',12), 
                           fg="white", 
                           bg="#4A4459", 
                           padx=10,
                           pady=10).pack()
    #Text box
    phone_entry = Entry(new_window, font=('Courier New', 12))
    phone_entry.pack(pady=20)
    #Submit Button
    def on_submit():
        return
    submit_button = Button(new_window, 
                           text="Submit", 
                           command=on_submit,
                           font=('Courier New', 12), 
                           bg="#00C3EB", 
                           fg="black", 
                           activebackground='#FF0000', 
                           activeforeground='white',
                           width=20)
    submit_button.pack()
    main.withdraw()  #closes main window

#Function for virus total 
def virusTotal_window():
    new_window = tk.Toplevel(main)
    new_window.title("Virus Total")
    new_window.geometry("600x600")
    new_window.config(background="#4A4459")
    #Text in the Window
    tk.Label(new_window,
             text="URL or Files", 
             font=('Courier New',12), 
             fg="white", 
             bg="#4A4459", 
             padx=10,
             pady=10).pack()
    #File open
    def openFile():
        filepath = filedialog.askopenfilename()
        print(filepath)
    button = tk.Button(new_window,
                    text="Open", 
                    command=openFile,
                    font=('Courier New', 12), 
                    bg="#00C3EB", 
                    fg="black", 
                    activebackground='#FF0000', 
                    activeforeground='white',
                    width=20)
    button.pack(pady=40)
    #Text box for url
    entry = Entry(new_window, font=('Courier New', 12))
    entry.pack(pady=10)
    #Submit Button
    def on_submit():
        return
    submit_button = Button(new_window, 
                           text="Submit", 
                           command=on_submit,
                           font=('Courier New', 12), 
                           bg="#00C3EB", 
                           fg="black", 
                           activebackground='#FF0000', 
                           activeforeground='white',
                           width=20)
    submit_button.pack(pady=20)

    main.withdraw()  #closes main window

#Main window buttons
malShare = Button(main, 
                  text='Malshare', 
                  command=malShare_window, 
                  font=('Courier New', 12), 
                  bg="#00C3EB", 
                  fg="black", 
                  activebackground='#FF0000', 
                  activeforeground='white',
                  width=20).pack(pady=5)

urlScan = Button(main,text='URLScan',
                 command=urlScan_window,
                 font=('Courier New', 12),  
                 bg="#00C3EB", 
                 fg="black", 
                 activebackground='#FF0000', 
                 activeforeground='white',
                 width=20).pack(pady=20)

webOfTrust = Button(main,
                    text='WebofTrust',
                    command=webOfTrust_window,
                    font=('Courier New', 12), 
                    bg="#00C3EB", 
                    fg="black", 
                    activebackground='#FF0000', 
                    activeforeground='white',
                    width=20)
webOfTrust.pack(pady=0)

veriPhone = Button(main,
                   text='Veriphone',
                   command=veriPhone,
                   font=('Courier New', 12), 
                   bg="#00C3EB", 
                   fg="black", 
                   activebackground='#FF0000', 
                   activeforeground='white',
                   width=20).pack(pady=20)

virusTotal = Button(main,
                    text='VirusTotal',
                    command=virusTotal_window,
                    font=('Courier New', 12), 
                    bg="#00C3EB", 
                    fg="black", 
                    activebackground='#FF0000', 
                    activeforeground='white',
                    width=20).pack(pady=10)

End = Button(main,text='Exit')
End.config(command=main.quit,
           font=('Courier New', 12), 
           bg="#00C3EB", 
           fg="black", 
           activebackground='#FF0000', 
           activeforeground='white',
           width=20)
End.pack(pady=20)
#ends application

main.mainloop()
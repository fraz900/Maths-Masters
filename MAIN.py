import tkinter as tk
from PIL import Image, ImageTk
from online.client import *

def login():
    c = connection()
    top = tk.Tk()

    top.geometry("400x500")

    name_var=tk.StringVar()
    passw_var=tk.StringVar()

    def submit():
     
        name=name_var.get()
        password=passw_var.get()
         
        print("The name is : " + name)
        print("The password is : " + password)
        try:
            check = c.login(name,password)
            if check:
                top.destroy()
                main()
        except:
            a.config(text="username or password incorrect",fg="red")
        name_var.set("")
        passw_var.set("")

    txt_frm = tk.Frame(top,width=600,height=600,bg="red")

    name_label = tk.Label(top, text = 'Username', font=('calibre',10, 'bold'))  
    name_entry = tk.Entry(top,textvariable = name_var, font=('calibre',10,'normal'))
    passw_label = tk.Label(top, text = 'Password', font = ('calibre',10,'bold'))
    passw_entry = tk.Entry(top, textvariable = passw_var, font = ('calibre',10,'normal'), show = '*')
    sub_btn=tk.Button(top,text = 'Submit', command = submit)
    
    a = tk.Label(top,text="",font=("calibre",10))
    
    image = Image.open("gui_resources/ball.png")

    resized_image= image.resize((300,205), Image.ANTIALIAS)
    new_image= ImageTk.PhotoImage(resized_image)

    photo = ImageTk.PhotoImage(resized_image)

    label = tk.Label(top, image = photo)
    label.image = photo
    label.grid(row=0,column=1)
    name_label.grid(row=1,column=0)
    name_entry.grid(row=1,column=1)
    passw_label.grid(row=2,column=0)
    passw_entry.grid(row=2,column=1)
    sub_btn.grid(row=3,column=1)
    a.grid(row=4,column=1)


    top.resizable(False,False)
    top.mainloop()

def main():
    print("ayyyyy")
print(login())

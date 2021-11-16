import tkinter as tk
from PIL import Image, ImageTk
from online.client import *
import os
class GUI():

    def __init__(self):
        self.c = connection()

    def start(self):
        if self.c.ping():
           self.login()
        else:
            self.error("connection error, cannot connect to server.\n Please try again later")

    def error(self,error_message):
        top = tk.Tk()

        top.geometry("300x100")
        
        error_label = tk.Label(top, text = error_message, font=('calibre',10, 'bold'))  
        error_label.config(fg="red")
        error_label.grid(row=3,column=1)
        top.resizable(False,False)
        top.mainloop()
        
    def login(self):
        
        c = connection()
        top = tk.Tk()
        canvas=tk.Canvas(top, width=400, height=500)
        canvas.grid(row=1,column=0)

        top.geometry("400x500")
        frame = tk.Frame(top)
        name_var=tk.StringVar()
        passw_var=tk.StringVar()

        def submit():
            name=name_var.get()
            password=passw_var.get()
             
            print("The name is : " + name)
            print("The password is : " + password)
            start_loading()
            try:
                check = self.c.login(name,password)
                if check:
                    top.destroy()
                    self.main()
            except:
                login_error.config(text="username or password incorrect",fg="red")
            name_var.set("")
            passw_var.set("")

        txt_frm = tk.Frame(top,width=400,height=250)
        txt_frm.grid(row=0,column=0, sticky="n")
        name_label = tk.Label(txt_frm, text = 'Username', font=('calibre',10, 'bold'))  
        name_entry = tk.Entry(txt_frm,textvariable = name_var, font=('calibre',10,'normal'))
        passw_label = tk.Label(txt_frm, text = 'Password', font = ('calibre',10,'bold'))
        passw_entry = tk.Entry(txt_frm, textvariable = passw_var, font = ('calibre',10,'normal'), show = '*')
        sub_btn=tk.Button(txt_frm,text = 'Submit', command = submit)
        
        login_error = tk.Label(txt_frm,text="",font=("calibre",10))

        logo_image = Image.open("gui_resources/ball.png")

        resized_image= logo_image.resize((300,205), Image.ANTIALIAS)
        new_image= ImageTk.PhotoImage(resized_image)

        photo = ImageTk.PhotoImage(resized_image)
        label = tk.Label(txt_frm, image = photo)
        label.image = photo
        label.grid(row=0,column=1)
        name_label.grid(row=1,column=0)
        name_entry.grid(row=1,column=1)
        passw_label.grid(row=2,column=0)
        passw_entry.grid(row=2,column=1)
        sub_btn.grid(row=3,column=1)
        login_error.grid(row=4,column=1)

        imagelist = []
        things = os.listdir("gui_resources/loading")
        for item in things:
            imagelist.append(os.path.join("gui_resources/loading",item))
        giflist = []
        for imagefile in imagelist:
            photo = Image.open(imagefile)
            giflist.append(photo)
        timer_id = None
        def start_loading(n=0):
            global timer_id
            gif = giflist[n%len(giflist)]
            resizer = ImageTk.PhotoImage(gif.resize((50,50),Image.ANTIALIAS))
            canvas.create_image(235,25, image=resizer)
            timer_id = top.after(100, start_loading, n+1)
        
        #resizer = ImageTk.PhotoImage(giflist[2].resize((50,50),Image.ANTIALIAS))
        #canvas.create_image(235,25, image=resizer)


        top.resizable(True,True)
        top.mainloop()

        #TODO
        #1. make gif work please
        
    def main(self):
        print("ayyyyy")

if __name__ == "__main__":
    g = GUI()
    g.start()

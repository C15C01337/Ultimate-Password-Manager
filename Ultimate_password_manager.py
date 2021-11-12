import hashlib
import sqlite3
from functools import partial
from tkinter import *
from tkinter import simpledialog
from tkinter import ttk
from random import randint
import tkinter



# Let's write the database Code where I am using sqlite db to store password locally
with sqlite3.connect("password_locker.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Create PopUp window

def popUp(text):
    ans = simpledialog.askstring("input string", text)

    return ans

# Initiate Display Window


display = Tk()
display.update()

display.title("Ultimate_Password_Manager")
display.title("Created by Bishal Aryal - Ethical Hacking Batch 30 ")


def hashedPass(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1

#   Designing master key display window
bg = PhotoImage(file='locker.png')
my_label = Label(display, image=bg)
my_label.place(x=0, y=0, relwidth=1, relheight=1)

def firstScreen():
    display.geometry("700x600")
    
    lbl = Label(display, text="Create Master Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(display, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(display, text="Confirm Master Key")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(display, width=20, show="*")
    txt1.pack()

    

    def saveMasterkey():
        if txt.get() == txt1.get():
            hashedPassword = hashedPass(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [hashedPassword])
            db.commit()
            lockerScreen()

        else:
            lbl.config(text="Please Re-enter Passwords don't match")

    btn = Button(display, text="Save",bg= 'yellow', command=saveMasterkey)
    btn.pack(pady=5)
    
    


#   Login Page of Ultimate Password Manager 

def loginPage():
    display.geometry("700x600")

    lbl = Label(display, text="Enter Master Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(display, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(display)
    lbl1.pack()

    def getMasterKey():
        checkhashedpassword = hashedPass(txt.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkhashedpassword])

        return cursor.fetchall()

    def checkPswd():
        password = getMasterKey()

        if password:
            lockerScreen()

        else:
            txt.delete(0, 'end')
            lbl1.config(text="Sorry Wrong Password")

    btn = Button(display, text="Submit", bg='yellow', command=checkPswd)
    btn.pack(pady=5)

#   Ultimate password manager functionalities #

def passGen():
    # Password Generating display.
    display = Tk()

    display.title("Advanced Password Generator")

    myPassword = chr(randint(33,126))

    def newRandom():
        passEntry.delete(0, END)
        pwLength = int(noEntry.get())

        pswd = ""

        for x in range(pwLength):
            pswd += chr(randint(33, 126))

        passEntry.insert(0, pswd)

    def clipper():
        display.clipboard_clear()
        display.clipboard_append(passEntry.get())
        tkinter.messagebox.showinfo("Random Password","Copied Successfully.")


    # Label frame for asking user input
    lf = LabelFrame(display, text="How many characters do you need in your password?")
    lf.pack(pady=24)

    # Creating Entry Box for number of characters
    noEntry = Entry(lf, font=("Helvetica", 15))
    noEntry.pack(pady=24, padx=24)

    # Now entry box for returned password.
    passEntry = Entry(display, text="", font=("Helvetica", 15), bd=0, bg="systembuttonface")
    passEntry.pack(pady=24)

    # Frame for buttons.
    myFrame = Frame(display)
    myFrame.pack(pady=24)

    # Create buttons
    genButton = Button(myFrame, text="Generate Password", command=newRandom)
    genButton.grid(row=0, column=0, padx=10)

    clipButton = Button(myFrame, text="Copy to Clipboard", command=clipper)
    clipButton.grid(row=0, column=1, padx=10)





def lockerScreen():
    for widget in display.winfo_children():
        widget.destroy()

    def newEntry():
        firstText = "Website"
        secondText = "Account"
        thirdText = "Password"

        website = popUp(firstText)
        account = popUp(secondText)
        password = popUp(thirdText)

        insert_fields = """INSERT INTO vault(website, account, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, account, password))
        db.commit()
        lockerScreen()

    def updatePass(input):
        update = "Type new password"
        password = popUp(update)
        update_password = "UPDATE vault SET password = ? WHERE id = ?"
        cursor.execute(update_password, (password, input,))
        db.commit()
        tkinter.messagebox.showinfo("Password","Password Updated Successfully.")
        lockerScreen()

    def deleteEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        tkinter.messagebox.showinfo("Info","Deleted Successfully.")
        lockerScreen()

    def copyAccount(input):
        display.clipboard_clear()
        display.clipboard_append(input)
        tkinter.messagebox.showinfo("Account","Account Copied Successfully.")

    def copyPassword(input):
        display.clipboard_clear()
        display.clipboard_append(input)
        tkinter.messagebox.showinfo("Password","Password Copied Successfully.")

#   display layout #

    display.geometry("750x550")
    main_frame = Frame(display)
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = Frame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")

    lbl = Label(second_frame, text="Ultimate_Password_Manager")
    lbl.grid(column=2)

    btn2 = Button(second_frame, text="Generate Password", command=passGen)
    btn2.grid(column=2, pady=10)

    btn = Button(second_frame, text="Add New Entry", command=newEntry)
    btn.grid(column=4, pady=10)

    lbl = Label(second_frame, text="Website")
    lbl.grid(row=2, column=0, padx=40)
    lbl = Label(second_frame, text="Account")
    lbl.grid(row=2, column=1, padx=40)
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=40)

    cursor.execute("SELECT * FROM vault")

#   Buttons Layout #

    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            lbl1 = Label(second_frame, text=(array[i][1]))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(second_frame, text=(array[i][2]))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(second_frame, text=(array[i][3]))
            lbl3.grid(column=2, row=i + 3)
            btn2 = Button(second_frame, text="Copy Account", command=partial(copyAccount, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = Button(second_frame, text="Copy Password", command=partial(copyPassword, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = Button(second_frame, text="Update", command=partial(updatePass, array[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = Button(second_frame, text="Delete", command=partial(deleteEntry, array[i][0]))
            btn.grid(column=6, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginPage()
else:
    firstScreen()

display.mainloop()




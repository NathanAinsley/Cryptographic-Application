# -*- coding: utf-8 -*-
"""
Created on Fri Oct 29 18:54:16 2021

@author: nathan ainsley 18028669
"""

import sqlite3
import os
import zipfile
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from ttkwidgets.autocomplete import AutocompleteEntry
from tkinter.scrolledtext import ScrolledText
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey.RSA import construct
from Cryptodome.Cipher import AES

database = 'user.db'
con = sqlite3.connect(database)
cur = con.cursor()
cur.execute('''CREATE TABLE  IF NOT EXISTS User(
                                Username text ,
                                Password text,
                                UserGroup text, 
                                Salt text,
                                n text,
                                e text,
                                d text,
                                PRIMARY KEY (Username))''')
cur.execute('''CREATE TABLE  IF NOT EXISTS Records(
                                Username text,
                                Path text,
                                keys text,
                                nonce text,
                                tag text,
                                HASH text,
                                new text,
                                type text,
                                PRIMARY KEY(keys, nonce, tag)
                                FOREIGN KEY (Username) REFERENCES User(Username))''')
con.commit()
con.close()
def notifications():
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT COUNT(*) FROM Records WHERE new=? AND Username = ? AND type = ?''', (1,LogUsername_Var.get(),"rsa"))
    user1=cur.fetchall()
    return(user1[0][0])
def verifyPassword():
    validated=False
    if (NewPassword_Var.get() == NewPassword_Var2.get()):
        validated=True
    return validated
def verifyName():
    user_name = NewUsername_Var.get()
    verify = False
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT 1 FROM User WHERE Username=?''', (user_name,))
    user1=cur.fetchall()
    if (len(user1)==0):
        verify = True
    return verify
def RSA_Key_Gen():
    random_generator = Random.new().read
    key = RSA.generate(4096)
    n = key.n
    e = key.e
    d = key.d
    N = str(n)
    E = str(e)
    D = str(d)
    return N,E,D
def OutputKeys(SelectUserBox_Var,FolderPathBox):
    #inject with {name}'; Select * From User Where e <> ' to get all data into file
    path = FolderPathBox.get("1.0",END)#define location to save to
    f = folder_selected + "/Public Key OutPut.csv"#creates file to save to
    statement = "SELECT Username, n,e FROM User WHERE Username='"+SelectUserBox_Var.get()+"';"#statement that can be injected upon
    print(statement)
    statement1 = statement.split(";")#allows it to be injected
    for i in statement1:#looks at each individual sql statement, if not injected then will be 1
        if (len(i) > 0):
            file = open(f,"w")#opens file
            con=sqlite3.connect(database)#connects to database
            con.row_factory = sqlite3.Row#gets column names for later
            cur = con.cursor()
            cur.execute(i)#executes the statment
            user1=cur.fetchall()#gets whats returned
            for j in user1:
                file.write(str(dict(j))+"\n")#will only ever save the last statement ran, as it will save over the first statement
            con.close()#close db
            file.close()#close file
    messagebox.showinfo("success", f"Keys have been exported to {f}.")#shows a message to say it was successfull
def Get_File_To_Decrypt(FilePathBox):
    var = FilePathBox.get("1.0",'end-2c')
    return var
def Encrypt_User_Password(password,salt):
    key = PBKDF2(password, salt, 64, count=100000, hmac_hash_module=SHA512)
    return key
def MakeAESPassword(password,salt):
    key = PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA512)
    return key
def clearWindow():
    for widget in root.winfo_children():
        widget.destroy()
def TogglePasswords(PassEnter,PassEnter2,TogglePassword):
    if (PassEnter["show"] == "*"):
        PassEnter.configure(show="")
        PassEnter2.configure(show="")
        TogglePassword.configure(text="Hide Passwords")
    else:
        PassEnter.configure(show="*")
        PassEnter2.configure(show="*")
        TogglePassword.configure(text="Show Passwords")
def TogglePasswordsLog(PassEnter,TogglePassword):
    if (PassEnter["show"] == "*"):
        PassEnter.configure(show="")
        TogglePassword.configure(text="Hide Password")
    else:
        PassEnter.configure(show="*")
        TogglePassword.configure(text="Show Password")
def SwapGroupsIndividuals(Users,Groups):
    if (Group_Individual["text"]=="Individual"):
        SelectUserBox.configure(completevalues=Groups)
        SelectUser.configure(text="Select Group")
        SelectUser.place(x=75,y=150,width=75,height=20)
        Group_Individual.configure(text = "Group")
    elif (Group_Individual["text"]=="Group"):
        SelectUserBox.configure(completevalues=Users)
        SelectUser.configure(text="Select Individual")
        SelectUser.place(x=60,y=150,width=90,height=20)
        Group_Individual.configure(text = "Individual")
def resetUser():
    Logged_In_User=""
def browseFiles(FilePathBox):
    global filenames
    filenames = filedialog.askopenfilenames(initialdir = "/", title = "Select a File", filetypes = (("Text files","*.txt*"),("Encrypted files","*.enc*"), ("all files", "*.*")))
    for f in filenames:
        FilePathBox.insert(END, f + '\n')
def getFile(FilePathBox):
    global filename
    filename = filedialog.askopenfilename(initialdir = "/", title = "Select a File", filetypes = (("Encrypted files","*.enc*"), ("all files", "*.*")))
    FilePathBox.insert(END, filename)
def browseFolders(FolderPathBox):
    global folder_selected
    folder_selected = filedialog.askdirectory()
    FolderPathBox.insert(END, folder_selected + '\n')
def Compress(var):
    fName = var+".zip"
    z = zipfile.ZipFile(fName,"w", zipfile.ZIP_DEFLATED)
    for f in filenames:
        z.write(f, os.path.basename(f))
    z.close()
    return fName
def PullUserNames():
    Users = []
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT Username FROM User''')
    user1=cur.fetchall()
    for j in user1:
        Users.append(j[0])
    return Users
def PullGroups():
    Groups = []
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT UserGroup FROM User''')
    user1=cur.fetchall()
    for j in user1:
        if j not in Groups:
            Groups.append(j[0])
    return Groups
def ToggleNewOrAll(NewOrAll,N,ResultsBox):
    if (NewOrAll["text"] == "New"):
        NewOrAll.configure(text = "All")
        N = "All"
        populateResultsBox(N,ResultsBox)
    elif (NewOrAll["text"] == "All"):
        NewOrAll.configure(text = "New")
        N = "New"
        populateResultsBox(N,ResultsBox)
def populateResultsBox(N,ResultsBox):
    ResultsBox.config(state=NORMAL)
    ResultsBox.delete('1.0', END)
    if (N=="New"):
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('''SELECT Path FROM Records WHERE new=? AND Username = ? AND type = ?''', (1,LogUsername_Var.get(),"rsa",))
        user1=cur.fetchall()
        for f in user1:
            ResultsBox.insert(END, f[0] + '\n')
        con.close()
    elif (N=="All"):
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('''SELECT Path FROM Records WHERE Username = ? AND type = ?''', (LogUsername_Var.get(),"rsa",))
        user1=cur.fetchall()
        for f in user1:
            ResultsBox.insert(END, f[0] + '\n')
        con.close()
    ResultsBox.config(state=DISABLED)
def Get_File_Decryption(ResultsBox):
    File_To_Decrypt = ResultsBox.get(tk.SEL_FIRST, tk.SEL_LAST)
    return File_To_Decrypt
def AddUser():
    checkvalidated = verifyPassword()
    uvalidated = verifyName()
    if (checkvalidated == True & uvalidated == True):
        USERNAME = NewUsername_Var.get()
        PASSWORD = NewPassword_Var.get()
        GROUP = Group_Var.get()
        salt = get_random_bytes(64)
        SALT = salt.hex()
        n,e,d = RSA_Key_Gen()
        enc_password = Encrypt_User_Password(PASSWORD,salt)
        ENC_PASSWORD = enc_password.hex()
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute("INSERT INTO User VALUES (?, ?, ?, ?, ?, ?,?)", (USERNAME, ENC_PASSWORD,GROUP,SALT,n,e,d))
        con.commit()
        con.close()
        messagebox.showinfo("Account Created", f"Welcome {USERNAME}, your account has now been created. Please log in to access your files.")
        clearWindow()
        LoginReturn()
    elif(checkvalidated == False and  uvalidated == False):
        messagebox.showerror("Error","Passwords do not match, please use the same password + Username already used, please select a different Username")
    elif(checkvalidated == False and  uvalidated == True):
        messagebox.showerror("Error","Passwords do not match, please use the same password")
    elif(checkvalidated == True and  uvalidated == False):
        messagebox.showerror("Error","Username already used, please select a different Username")
def hasher(BYTES):
    hash_object = SHA512.new(data=BYTES)
    return hash_object.hexdigest()
def HashValidation(HASH,User):
    validated = False
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT HASH FROM Records WHERE HASH=? AND Username=?''', (HASH,User))
    user1=cur.fetchall()
    con.close()
    if (len(user1)==0):
        validated = True
    return validated
def AESEncryption(bytes,aes_key):
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    (cipher, tag) = aes_cipher.encrypt_and_digest(bytes)
    nonce = aes_cipher.nonce
    return cipher, nonce, tag
def AESDecryption(bytes,aes_key,nonce, tag):
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
    decrypted = aes_cipher.decrypt_and_verify(bytes, tag)
    return decrypted
def RSAEncryptCORE(User,CompressedFile,multi):
    done = False
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT n,e FROM User WHERE Username=?''', (User,))
    user1=cur.fetchall()
    pubkey = construct((int(user1[0][0]),int(user1[0][1])))
    aes_key = get_random_bytes(32)
    pt_file = open(CompressedFile,'rb')
    bytes = pt_file.read()
    filebytes = bytes
    HASH = hasher(filebytes)
    validated=HashValidation(HASH,User)
    if(validated == True):
        enc_bytes, nonce, tag = AESEncryption(filebytes,aes_key)
        RSAencryptor = PKCS1_OAEP.new(pubkey)
        enc_key = RSAencryptor.encrypt(aes_key)
        if (multi == 0):
            enc_to= str(folder_selected) + "/" + CompressedFile + ".enc"
        elif(multi ==1):
            enc_to= str(folder_selected) + "/" + "("+User+")" + CompressedFile + ".enc"
        enc_file = open(enc_to,'wb')
        enc_file.write(enc_bytes)
        pt_file.close()
        enc_file.close()
        cur.execute("INSERT INTO Records VALUES (?, ?, ?,?,?, ?,?,?)",  (User,enc_to,enc_key,nonce,tag,HASH,1,"rsa",))
        con.commit()
        con.close()
        done = True
    return done
def RSAEncrypt(SaveAsBox_Var):
    multi = 0
    CompressedFile = Compress(SaveAsBox_Var.get())
    if (Group_Individual["text"]=="Individual"):
        User = SelectUserBox_Var.get()
        done = RSAEncryptCORE(User,CompressedFile,multi)
        if (done == True):
            messagebox.showinfo("File encrypted", f"File: {CompressedFile} has been encrypted using {User}'s public key.")
            os.remove(CompressedFile)
        else:
            messagebox.showerror("Error","These Files have not been updated since the last encryption, update them and try again")
    elif (Group_Individual["text"]=="Group"):
        multi = 1
        Group = SelectUserBox.get()
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('''SELECT Username FROM User WHERE UserGroup=?''', (Group,))
        user1=cur.fetchall()
        con.close()
        for name in user1:
            user = name[0]
            done = RSAEncryptCORE(user,CompressedFile,multi)
            if (done == True):
                messagebox.showinfo("File encrypted", f"File: {CompressedFile} has been encrypted using User's: {user} public key as they are in the {Group} group.")
            else:
                messagebox.showerror("Error","These Files have not been updated since the last encryption, update them and try again")
        os.remove(CompressedFile)
def RSADecrypt(N,ResultsBox):
    try:
        File_To_Decrypt = Get_File_Decryption(ResultsBox)
        User = LogUsername_Var.get()
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('''SELECT n,e,d FROM User WHERE Username=?''', (User,))
        user1=cur.fetchall()
        prikey = construct((int(user1[0][0]),int(user1[0][1]),int(user1[0][2])))
        cur.execute('''SELECT keys,nonce,tag FROM Records WHERE Path=? AND Username = ? ''', (File_To_Decrypt,User,))
        user1=cur.fetchall()
        key = user1[0][0]
        nonce = user1[0][1]
        tag = user1[0][2]
        RSAencryptor = PKCS1_OAEP.new(prikey)
        dec_key = RSAencryptor.decrypt(key)
        cipher_file = open(File_To_Decrypt,'rb')
        bytes = cipher_file.read()
        dec_bytes = AESDecryption(bytes,dec_key,nonce, tag)
        base = os.path.splitext(os.path.basename(File_To_Decrypt))[0]
        dec_to = str(folder_selected)+"/"+base
        dec_file = open(dec_to,'wb')
        dec_file.write(dec_bytes)
        cipher_file.close()
        dec_file.close()
        
        cur.execute('''UPDATE Records SET new = ? WHERE Path = ? AND Username = ?''',(0,File_To_Decrypt,User,))
        con.commit()
        con.close()
        messagebox.showinfo("File Decrypted", f"File: {File_To_Decrypt} has been DEcrypted and stored at {dec_to}.")
        populateResultsBox(N,ResultsBox)
    except:
        messagebox.showerror("Error","Error when trying to decrypt file, please check it still excists at the location shown")
def SymDecryption(Password_Var,FilePathBox):
    try:
        dec_key = Password_Var.get()
        con=sqlite3.connect(database)
        cur = con.cursor()
        cur.execute('''SELECT Username, nonce, tag FROM Records WHERE Path = ? ''',(filename,))
        user1=cur.fetchall()
        Username = user1[0][0]
        nonce = user1[0][1]
        tag = user1[0][2]
        cur.execute('''SELECT salt FROM User WHERE Username=?''', (Username,))
        user1=cur.fetchall()
        salt = user1[0][0]
        aes_key = MakeAESPassword(dec_key,salt)
        cipher_file = open(filename,'rb')
        bytes = cipher_file.read()
        dec_bytes = AESDecryption(bytes,aes_key,nonce, tag)
        base = os.path.splitext(os.path.basename(filename))[0]
        dec_to = str(folder_selected)+"/"+base
        dec_file = open(dec_to,'wb')
        dec_file.write(dec_bytes)
        cipher_file.close()
        dec_file.close()
        con.commit()
        con.close()
        messagebox.showinfo("File Decrypted", f"File: {filename} has been decrypted using a secret password.")
    except:
        messagebox.showerror("Error","Error when trying to decrypt file, check the password and try again")
def SymEncryption(SaveAsBox_Var,Password_Var):
    CompressedFile = Compress(SaveAsBox_Var.get())
    password = Password_Var.get()
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT salt FROM User WHERE Username=?''', (Log_user_name,))
    user1=cur.fetchall()
    salt = user1[0][0]
    key = MakeAESPassword(password,salt)
    pt_file = open(CompressedFile,'rb')
    bytes = pt_file.read()
    filebytes = bytes
    HASH = hasher(filebytes)
    validation = HashValidation(HASH,Log_user_name)
    if (validation == True):
        enc_bytes, nonce, tag = AESEncryption(filebytes,key)
        f = CompressedFile+ ".enc"
        enc_to = str(folder_selected) + "/" + f
        enc_file = open(enc_to,'wb')
        enc_file.write(enc_bytes)
        pt_file.close()
        enc_file.close()
        cur.execute("INSERT INTO Records VALUES (?, ?, ?, ?,?,?,?,?)",  (Log_user_name,enc_to,0,nonce,tag,HASH,"","aes",))
        con.commit()
        con.close()
        messagebox.showinfo("File encrypted", f"File: {CompressedFile} has been encrypted using a secret password.")
        os.remove(CompressedFile)
    else:
        messagebox.showerror("Error","These Files have not been updated since the last encryption, update them and try again")
def AESMenu():
    LName = Label (root, text=Logged_In_User,font=("Arial",25))
    LName.place(x=0,y=0)
    LogOut = Button(root, text="Log Out", command = lambda:[clearWindow(),Loginmenu(),resetUser()])
    LogOut.place(x=450,y=0,width=50,height=50)
    Return = Button(root, text="Return", command = lambda:[clearWindow(),EncMenu()])
    Return.place(x=400,y=0,width=50,height=50)
    Decrypt = Button(root, text="Decrypt", command = lambda:[clearWindow(),AESDECMenu()])
    Decrypt.place(x=350,y=0,width=50,height=50)
    SelectFile = Button(root, text="Select Files", command = lambda:[browseFiles(FilePathBox)])
    SelectFile.place(x=75,y=100,width=75,height=40)
    FilePathBox = ScrolledText(root)
    FilePathBox.place(x=150, y=100,width=300,height=40)
    PasswordLabel = Label(root, text="Password")
    PasswordLabel.place(x=75,y=150,width=75,height=20)
    Password_Var = StringVar()
    PasswordBox = Entry(root, textvariable = Password_Var)
    PasswordBox.place(x=150, y=150,width=300,height=20)
    EncryptFiles = Button(root, text="Encrypt Files", command = lambda:[SymEncryption(SaveAsBox_Var,Password_Var)])
    EncryptFiles.place(x=200,y=400,width=75,height=35)
    SelectFolder = Button(root, text="Select Folder", command = lambda:[browseFolders(FolderPathBox)])
    SelectFolder.place(x=75,y=250,width=75,height=40)
    FolderPathBox = Text(root)
    FolderPathBox.place(x=150, y=250,width=300,height=40)
    SaveAs = Label(root, text="SaveAs Name")
    SaveAs.place(x=75,y=300,width=75,height=20)
    SaveAsBox_Var = StringVar()
    SaveAsBox = Entry(root, textvariable = SaveAsBox_Var)
    SaveAsBox.place(x=150, y=300,width=300,height=20)
def AESDECMenu():
    LName = Label (root, text=Logged_In_User,font=("Arial",25))
    LName.place(x=0,y=0)
    LogOut = Button(root, text="Log Out", command = lambda:[clearWindow(),Loginmenu(),resetUser()])
    LogOut.place(x=450,y=0,width=50,height=50)
    Return = Button(root, text="Return", command = lambda:[clearWindow(),EncMenu()])
    Return.place(x=400,y=0,width=50,height=50)
    Encrypt = Button(root, text="Encrypt", command = lambda:[clearWindow(),AESMenu()])
    Encrypt.place(x=350,y=0,width=50,height=50)
    SelectFile = Button(root, text="Select Files", command = lambda:[getFile(FilePathBox)])
    SelectFile.place(x=75,y=100,width=75,height=40)
    FilePathBox = ScrolledText(root)
    FilePathBox.place(x=150, y=100,width=300,height=40)
    PasswordLabel = Label(root, text="Password")
    PasswordLabel.place(x=75,y=150,width=75,height=20)
    Password_Var = StringVar()
    PasswordBox = Entry(root, textvariable = Password_Var)
    PasswordBox.place(x=150, y=150,width=300,height=20)
    DecryptFiles = Button(root, text="Decrypt File", command = lambda:[SymDecryption(Password_Var,FilePathBox)])
    DecryptFiles.place(x=200,y=360,width=75,height=35)
    SelectFolder = Button(root, text="Select Folder", command = lambda:[browseFolders(FolderPathBox)])
    SelectFolder.place(x=75,y=250,width=75,height=40)
    FolderPathBox = Text(root)
    FolderPathBox.place(x=150, y=250,width=300,height=40)
def UtilityScreen():
    Return = Button(root, text="Return", command = lambda:[clearWindow(),EncMenu()])
    Return.place(x=450,y=0,width=50,height=50)
    Users = PullUserNames()
    SelectUser = Label(root, text="Select User")
    SelectUser.place(x=75,y=150,width=75,height=20)
    SelectUserBox_Var = StringVar()
    SelectUserBox = AutocompleteEntry(root, textvariable = SelectUserBox_Var,completevalues=Users)
    SelectUserBox.place(x=150, y=150,width=300,height=20)
    SelectFolder = Button(root, text="Select Destination", command = lambda:[browseFolders(FolderPathBox)])
    SelectFolder.place(x=50,y=180,width=125,height=40)
    FolderPathBox = Text(root)
    FolderPathBox.place(x=175, y=180,width=275,height=40)
    PrintKeys = Button(root, text="Print Public key to file", command = lambda:[OutputKeys(SelectUserBox_Var,FolderPathBox)])
    PrintKeys.place (x=200,y=350,width=125,height=30)
def RSADecScreen():
    Return = Button(root, text="Return", command = lambda:[clearWindow(),EncMenu()])
    Return.place(x=450,y=0,width=50,height=50)
    N="New"
    NewOrAll = Button(root, text="New", command = lambda:[ToggleNewOrAll(NewOrAll,N,ResultsBox)])
    NewOrAll.place (x=200,y=50,width=100,height=30)
    ResultsBox = ScrolledText(root)
    ResultsBox.place(x=50, y=100,width=400,height=200)
    populateResultsBox(N,ResultsBox)
    ResultsBox.config(state=DISABLED)
    SelectFolder = Button(root, text="Select Destination", command = lambda:[browseFolders(FolderPathBox)])
    SelectFolder.place(x=50,y=310,width=125,height=40)
    FolderPathBox = Text(root)
    FolderPathBox.place(x=175, y=310,width=275,height=40)
    Dec_File = Button(root, text="Decrypt Selected File", command = lambda:[RSADecrypt(N,ResultsBox)])
    Dec_File.place (x=200,y=350,width=125,height=30)
def RSAMenu():
    global SelectUserBox_Var, Group_Individual, SelectFolder, FolderPathBox, SelectUser, SelectUserBox
    Users = PullUserNames()
    Groups = PullGroups()
    LName = Label (root, text=Logged_In_User,font=("Arial",25))
    LName.place(x=0,y=0)
    LogOut = Button(root, text="Log Out", command = lambda:[clearWindow(),Loginmenu(),resetUser()])
    LogOut.place(x=450,y=0,width=50,height=50)
    Return = Button(root, text="Return", command = lambda:[clearWindow(),EncMenu()])
    Return.place(x=400,y=0,width=50,height=50)
    SelectFile = Button(root, text="Select Files", command = lambda:[browseFiles(FilePathBox)])
    SelectFile.place(x=75,y=100,width=75,height=40)
    FilePathBox = ScrolledText(root)
    FilePathBox.place(x=150, y=100,width=300,height=40)
    Group_Individual = Button(root, text="Individual", command = lambda:[SwapGroupsIndividuals(Users,Groups)])
    Group_Individual.place(x=200,y=350,width=75,height=35)
    SelectUser = Label(root, text="Select Individual")
    SelectUser.place(x=60,y=150,width=90,height=20)
    SelectUserBox_Var = StringVar()
    SelectUserBox = AutocompleteEntry(root, textvariable = SelectUserBox_Var,completevalues=Users)
    SelectUserBox.place(x=150, y=150,width=300,height=20)
    EncryptFiles = Button(root, text="Encrypt Files", command = lambda:[RSAEncrypt(SaveAsBox_Var)])
    EncryptFiles.place(x=200,y=400,width=75,height=35)
    SelectFolder = Button(root, text="Select Folder", command = lambda:[browseFolders(FolderPathBox)])
    SelectFolder.place(x=75,y=250,width=75,height=40)
    FolderPathBox = Text(root)
    FolderPathBox.place(x=150, y=250,width=300,height=40)
    SaveAs = Label(root, text="SaveAs Name")
    SaveAs.place(x=75,y=300,width=75,height=20)
    SaveAsBox_Var = StringVar()
    SaveAsBox = Entry(root, textvariable = SaveAsBox_Var)
    SaveAsBox.place(x=150, y=300,width=300,height=20)
def EncMenu():
    notificationammo = notifications()
    notification_string = str(notificationammo) + " New Files to Decrypt"
    LName = Label (root, text=Logged_In_User,font=("Arial",25))
    LName.place(x=0,y=0)
    LogOut = Button(root, text="Log Out", command = lambda:[clearWindow(),Loginmenu(),resetUser()])
    LogOut.place(x=450,y=0,width=50,height=50)
    AESButton = Button(root, text="Symmetric Encryption", command = lambda:[clearWindow(),AESMenu()])
    AESButton.place(x=175,y=175,width=150,height=75)
    RSAButton = Button(root, text="Asymmetric Encryption", command = lambda:[clearWindow(),RSAMenu()])
    RSAButton.place(x=175,y=250,width=150,height=75)
    UtilityButton = Button(root, text="Utility Functions", command = lambda:[clearWindow(),UtilityScreen()])
    UtilityButton.place(x=175,y=325,width=150,height=75)
    Notifications = Button(root, text=notification_string, command = lambda:[clearWindow(),RSADecScreen()])
    Notifications.place(x=300,y=0,width=150,height=50)
def LoginUser():
    global Logged_In_User, Log_user_name
    
    Log_user_name = LogUsername_Var.get()
    LogPassword = LogPassword_Var.get()
    con=sqlite3.connect(database)
    cur = con.cursor()
    cur.execute('''SELECT Password,Salt FROM User WHERE Username=?''', (Log_user_name,))
    user1=cur.fetchall()
    if (len(user1)==0):
        messagebox.showerror("Error","No user found with that Username")
    else:
        P = user1[0][0]
        S = user1[0][1]
        con.close()
        bS = bytes.fromhex(S)
        key = (Encrypt_User_Password(LogPassword, bS)).hex()
        if(key == P):
            Logged_In_User = "User: " + Log_user_name
            clearWindow()
            EncMenu()
        else:
            messagebox.showerror("Error","Password did not match")
def LoginReturn():
    global LogUsername_Var,LogPassword_Var
    LoginLabel = Label(root, text="Login", font=("Arial", 25))
    LoginLabel.place(x=200,y=50)
    Username = Label(root, text="Username: ")
    Username.place (x=100,y=100)
    LogUsername_Var = StringVar()
    UserEnter = Entry(root, textvariable = LogUsername_Var)
    UserEnter.place(x=175, y=100,width=200,height=20)
    Password = Label(root, text="Password: ")
    Password.place (x=100,y=150)
    LogPassword_Var = StringVar()
    PassEnter = Entry(root, textvariable = LogPassword_Var,show="*")#want to make it so you can toggle the show *
    PassEnter.place(x=175, y=150,width=200,height=20)
    TogglePassword = Button(root, text="Show Password", command = lambda:[TogglePasswordsLog(PassEnter,TogglePassword)])
    TogglePassword.place (x=200,y=200,width=100,height=30)
    LoginB = Button (root, text="Login", command = lambda:[ LoginUser()])
    LoginB.place (x=200,y=275,width=100,height=50)
def NewUserMenu():
    global NewUsername_Var,NewPassword_Var, NewPassword_Var2, Group_Var
    NewUserLabel = Label(root, text="New User", font=("Arial", 25))
    NewUserLabel.place(x=200,y=50)
    Return = Button(root, text="Return", command = lambda:[clearWindow(),Loginmenu()])
    Return.place(x=450,y=0,width=50,height=50)
    Username = Label(root, text="Username: ")
    Username.place (x=100,y=100)
    NewUsername_Var = StringVar()
    UserEnter = Entry(root, textvariable = NewUsername_Var)
    UserEnter.place(x=175, y=100,width=200,height=20)
    Password = Label(root, text="Password: ")
    Password.place (x=100,y=150)
    NewPassword_Var = StringVar()
    PassEnter = Entry(root, textvariable = NewPassword_Var,show="*")
    PassEnter.place(x=175, y=150,width=200,height=20)
    Password2 = Label(root, text="Verify Password: ")
    Password2.place (x=70,y=200)
    NewPassword_Var2 = StringVar()
    PassEnter2 = Entry(root, textvariable = NewPassword_Var2,show="*")
    PassEnter2.place(x=175, y=200,width=200,height=20)
    GroupLabel = Label(root, text="Enter Group: ")
    GroupLabel.place (x=70,y=230)
    Group_Var = StringVar()
    GroupEntry = Entry(root, textvariable = Group_Var)
    GroupEntry.place(x=175, y=230,width=200,height=20)
    TogglePassword = Button(root, text="Show Passwords", command = lambda:[TogglePasswords(PassEnter,PassEnter2,TogglePassword)])
    TogglePassword.place (x=200,y=250,width=100,height=30)
    CreateUser = Button (root, text="Create User", command = lambda:[ AddUser()])
    CreateUser.place (x=200,y=280,width=100,height=50)
def Loginmenu():
    LoginLabel = Label(root, text="Welcome", font=("Arial", 25))
    LoginLabel.place(x=200,y=50)
    Returning = Button (root, text = "Returning User", command = lambda: [clearWindow(), LoginReturn()])
    Returning.place (x=200,y=225,width=100,height=50)
    NewUser = Button (root, text="New User", command = lambda: [clearWindow(), NewUserMenu()])
    NewUser.place (x=200,y=275,width=100,height=50)
def root():
    global root
    root = tk.Tk()
    root.title('Nathan Ainsley (18028669) Encryption Application')
    root.resizable(False, False)
    root.geometry("500x500")
    Login = Button (root, text="Main Menu", command = lambda: [ clearWindow(),Loginmenu()])
    Login.place (x=200,y=225,width=100,height=50)
    root.mainloop()
root()
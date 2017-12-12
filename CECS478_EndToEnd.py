import os, requests, json, sys, threading, time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding   
from tkinter import *

#initiate global variables that wil be used for multiple methods
#window used for gui in tkinter
window = Tk()
token =""
currentUser = ""
chattingWith = ""
chatterPublicKey = ""
threadFlag = True

#this method will be used when encrypting a message
def Encryptor(message, PKPath):
    #make the primary key into and RSA key object
    RSAObj = serialization.load_pem_public_key(PKPath.encode(), backend=default_backend())

    #generate the key that will be used for AES encryption
    AESKey = os.urandom(32)
    #generate the IV that will be used for AES encryption
    iv = os.urandom(16)

    #create the AES encryptor using the AESkey, the IV and put it in CBC mode
    AESencryptor = Cipher(algorithms.AES(AESKey),
                                      modes.CBC(iv),
                                      backend=default_backend()
                                      ).encryptor()
    
    from cryptography.hazmat.primitives import padding
    #pad the message to 128 bits using PKCS7
    #this padder object will pad the message
    padder = padding.PKCS7(128).padder()
    #turn the message into bytes
    message = message.encode('utf-8')
    #pad the message
    Pmessage = padder.update(message)
    #finalize padding the message
    Pmessage += padder.finalize()

    #use the AES encryptor to encyprt the padded message
    cipher = AESencryptor.update(Pmessage) + AESencryptor.finalize()

    #generate an HMAC key that will be used to create a tag
    HMACKey = os.urandom(32)

    #create the tag using sha256
    tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag.update(cipher)
    t = tag.finalize()

    #concatenate the 2 keys and then encrypt it using RSA 
    concat = AESKey + HMACKey
    from cryptography.hazmat.primitives.asymmetric import padding
    #encyrpt the keys using the RSA object create with the receivers public key
    RSAcipher = RSAObj.encrypt(concat,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                            )
                               )

    #cryptography turns everything into bytes which dont work in JSON
    #THe bytes cannot be decoded into string so turn them into ints
    #this is the integer value of the two encrypted keys with length 256
    RSAint = int.from_bytes(RSAcipher, byteorder='big')
    #we need to save the size of the cipher message because it can change
    cipherSize = len(cipher)
    #turn the cipher message to an int
    cipherInt = int.from_bytes(cipher, byteorder='big')
    #turn the IV into ints 
    ivInt = int.from_bytes(iv, byteorder='big')
    #turn the tag into an int
    tagInt = int.from_bytes(t, byteorder='big')
    #dump all the data into a json object
    jsonData = {'RSAcipher': RSAint, 'cipherSize': cipherSize, 'cipher':cipherInt, 'iv': ivInt, 't': tagInt}
    return json.dumps(jsonData)

def Decryptor(jsonInfo, PrivKPath):
    #use two json loads because the request come with "" marks
    jsonData = json.loads(jsonInfo)
    jsonData = json.loads(jsonData)
    #grab all the information from the json and turn it into bytes
    RSAcipher = jsonData['RSAcipher'].to_bytes(256, byteorder='big')
    cipher = int(jsonData['cipher']).to_bytes(jsonData['cipherSize'], byteorder='big')
    iv = int(jsonData['iv']).to_bytes(16, byteorder='big')
    tag = int(jsonData['t']).to_bytes(32, byteorder='big')
    #do the opposite of encrypting
    from cryptography.hazmat.primitives.asymmetric import padding
    #load the private key of the user
    with open(PrivKPath, "rb") as key_file:
            #turn it into an RSA object 
            RSAObj = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    #use the RSA object to decrypt the concatenated keys
    concat = RSAObj.decrypt(RSAcipher,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                            )
                               )
    #the first half of the message is the AESKey
    AESKey = concat[:len(concat)//2]
    #The second half is the HMAC key
    HMACKey = concat[len(concat)//2:]
    #first create a tag again using the HMAC key and sha256 to recreate a tag
    tag2 = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    tag2.update(cipher)
    #check if the tasg are the same
    try:
        #Stops the program and "throws cryptography.exceptions.InvalidSignature" if tags aren't the same
        tag2.verify(tag)
        #use the AES key to create an AES decryptor
        AESdecryptor = Cipher(algorithms.AES(AESKey),
                                      modes.CBC(iv),
                                      backend=default_backend()
                                      ).decryptor()

        #get the plain text by decyrpting the cipher message
        plaintext = AESdecryptor.update(cipher) + AESdecryptor.finalize()

        #Unpad the plane text to get back the original message
        from cryptography.hazmat.primitives import padding
        unpadder = padding.PKCS7(128).unpadder()
        Pplaintext = unpadder.update(plaintext)
        Pplaintext += unpadder.finalize()

        #return the plaintext
        return Pplaintext

    #this means the tag was bad and invalid
    except cryptography.exceptions.InvalidSignature:
        print("The tag was invalid")

#this method is used to display the menu of the application
def Menu():
    #create the frame and labels and buttons
    frame = Frame(window)
    label = Label(frame, text="Welcome To The End To End Chat")
    label.pack(side="top", fill="x", pady=10)
    #if this button is pressed take them to registration
    registerButton = Button(frame, text="Register",
                        command=lambda: [frame.pack_forget(), Register()])
    #if login is pressed, send them to the login menu
    loginButton = Button(frame, text="Login and Chat",
                        command=lambda: [frame.pack_forget(), Login()])
    registerButton.pack()
    loginButton.pack()
    frame.pack()

#this method is used to display the register 
def Register():
    #create the frame, labels, entry boxes, and buttons
    frame = Frame(window)
    label = Label(frame, text="Wanted Username")
    label.grid(row=0, column = 0)
    entry = Entry(frame, bd = 5)
    entry.grid(row=0, column=1)
    label2 = Label(frame, text="Wanted Password")
    label2.grid(row=1, column = 0)
    entry2 = Entry(frame, bd = 5)
    entry2.grid(row=1, column=1)
    #once the button is pressed send the user to the submitted registration
    button = Button(frame, text="Submit",
                       command=lambda: [frame.grid_forget(), submitRegistration(entry.get(),entry2.get())])
    button.grid(row = 0, column = 2)
    frame.grid()

#this method will be used to submit the registration information
def submitRegistration(username, password):
    #get the url for the post request
    url = "https://fyjv.me/todoListApi/user"
    #create the payload that will be sent
    payload = "username=" + username + "&password=" + password
    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'cache-control': "no-cache",
        'postman-token': "b659e55e-d3ac-4e76-5e16-d027dfddcf53"
        }
    #send the information and get the response
    response = requests.request("POST", url, data=payload, headers=headers)
    #send user to confirmation screen
    registerConfirm()

#this method will be used to tell the user they were registered
def registerConfirm():
    #create the frame, labels, and buttons
    frame= Frame(window)
    label = Label(frame, text="Successfully Registered")
    label.pack(side="top", fill="x", pady=10)
    #when the button is pressed send the user back to the menu
    button = Button(frame, text="Go to the start menu",
                       command=lambda: [frame.pack_forget(), Menu()])
    button.pack()
    frame.pack()

#this method will be used to login the user
def Login():
    #crete the gui elements
    frame= Frame(window)
    label = Label(frame, text="Enter Username")
    label.grid(row=0, column = 0)
    entry = Entry(frame, bd = 5)
    entry.grid(row=0, column=1)
    label2 = Label(frame, text="Enter Password")
    label2.grid(row=1, column = 0)
    entry2 = Entry(frame, bd = 5)
    entry2.grid(row=1, column=1)
    #when the submit button is pressed send the user to login screen
    button = Button(frame, text="Submit",
                    command=lambda: [frame.grid_forget(), submitLogin(entry.get(), entry2.get())])
    button.grid(row = 0, column = 2)
    frame.grid()

#this method will used to as the user to login again if their information is wrong
def LoginAgain():
    #create the gui elements
    frame= Frame(window)
    label = Label(frame, text="Enter Username")
    label.grid(row=0, column = 0)
    entry = Entry(frame, bd = 5)
    entry.grid(row=0, column=1)
    label2 = Label(frame, text="Enter Password")
    label2.grid(row=1, column = 0)
    entry2 = Entry(frame, bd = 5)
    entry2.grid(row=1, column=1)
    label3 = Label(frame, text="Incorrect Username or Password")
    label3.grid(row=2, column = 0)
    #when the submit button is pressed send the user to the login screen
    button = Button(frame, text="Submit",
                    command=lambda: [frame.grid_forget(), submitLogin(entry.get(), entry2.get())])
    button.grid(row = 0, column = 2)
    frame.grid()

#this method will be used to input the login information
def submitLogin(username, password):
    #get the url of the post request to login
    url = "https://fyjv.me/todoListApi/user/login"
    #create the payload that wil; be sent
    payload = "username="+ username +"&password="+password
    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'cache-control': "no-cache",
        'postman-token': "ad657bd4-887e-7363-8fb2-965f055a817f"
        }
    #get the response of the request
    response = requests.request("POST", url, data=payload, headers=headers)
    #get the golbal variables
    global token
    global currentUser
    #save the username of the current user
    currentUser = username
    #get the JWT from the response
    token = response.text[1:-1]
    #if the token is "Error" then the login info was incorrect so make them login again
    if(token == "Error"):
        print("Incorrect username or password.")
        LoginAgain()

    #send them to the chat box
    else:
        print("Success")
        Chat()

#thi method wil be used to get the info of who you're going to contact
def Chat():
    #create the gui elements
    frame= Frame(window)
    label = Label(frame, text="Enter Username of Friend")
    label.grid(row=0, column = 0)
    entry = Entry(frame, bd = 5)
    entry.grid(row=0, column=1)
    label2 = Label(frame, text="Enter Friend's Public Key")
    label2.grid(row=1, column = 0)
    entry2 = Entry(frame, bd = 5)
    entry2.grid(row=1, column=1)
    #if the button is pressed then send the user to the chatbox
    button = Button(frame, text="Chat",
                    command=lambda: [frame.grid_forget(), ChatBox(entry.get(), entry2.get())])
    #if this button is pressed then send th user to the menu again
    button.grid(row = 0, column = 2)
    button2 = Button(frame, text="Return to Menu",
                    command=lambda: [frame.grid_forget(), Menu()])
    button2.grid(row = 3, column = 1)
    frame.grid()
    
#this method will be used to create a chatbox
def ChatBox(name, publicKey):
    #create the global variables
    global chattingWith
    global chatterPublicKey
    chattingWith = name
    chatterPublicKey = publicKey
    #create the message window
    messages = Text(window)
    messages.pack()

    #create the box to get the text    
    input_user = StringVar()
    input_field = Entry(window, text=input_user)
    input_field.pack(side=BOTTOM, fill=X)
    frame = Frame(window)

    #this method will be used to continuously keep checking if there are messages to read
    def getMessage():
        #keep repeating until the chat box is closed
        global threadFlag
        while(threadFlag):
            #wait 1 sec
            time.sleep(1)
            #get the url that will be used for the post request
            url = "https://fyjv.me/todoListApi/getm/"

            #get the payload that will be sent
            payload = "t="+ token + "&sender="+ chattingWith
            headers = {
                'content-type': "application/x-www-form-urlencoded",
                'cache-control': "no-cache",
                'postman-token': "264b3609-5a1a-e0d3-a19a-9746dae28d21"
                }

            #get the response from the server
            response = requests.request("POST", url, data=payload, headers=headers)
            data = response.text
            #if the response is not null decrypt the message
            if(data != "null"):
                
                deciphered = Decryptor(data, "C:\openssl-0.9.8r-i386-win32-rev2\private.pem")
                messages.insert(INSERT, '%s\n' % (name + ">" + deciphered.decode("utf-8")))
                print(deciphered.decode("utf-8"))
        print("done")

    #create the thread that will check if theres a message
    thread = threading.Thread(target=getMessage)
    thread.start()

    #this method will be used when the enter key is pressed
    def Enter_pressed(event):
        #get the input text to send it as a message
        input_get = input_field.get()
        print(input_get)
        #if input is !quit get the user out of the chatbox and end the thread
        if(input_get == "!quit"):
            global threadFlag
            threadFlag = False
            input_user.set('')
            messages.pack_forget()
            messages.destroy()
            input_field.destroy()
            frame.pack_forget()
            Menu()
            return "break"
        #if the message is something else encrypt and send it to the server
        else:
            messages.insert(INSERT, '%s\n' % (currentUser + ">" +input_get))
            #encrypt the message and get the JSON
            jsonInfo = Encryptor(input_get, publicKey)
            #get URL of the post request
            url = "https://fyjv.me/todoListApi/setm"
            #create payload to send
            payload = "t="+token + "&receiver=" + name +"&message="
            payload = payload + jsonInfo
            headers = {
                'content-type': "application/x-www-form-urlencoded",
                'cache-control': "no-cache",
                'postman-token': "df1be0a1-3d74-63b8-ce9f-e63d909553a5"
                }
            #get response and display to the user
            response = requests.request("POST", url, data=payload, headers=headers)
            input_user.set('')
            return "break"


    
    input_field.bind("<Return>", Enter_pressed)
    
    frame.pack()


#run menu    
Menu()

window.mainloop()
        

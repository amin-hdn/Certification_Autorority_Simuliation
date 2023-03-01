import hashlib
import tkinter as tk
from tkinter import ttk

import crypto
from crypto.PublicKey import RSA
from crypto.Cipher import PKCS1_OAEP
from crypto import Random
import binascii

class Root(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Generator")
        self.geometry("600x400")
        self.resizable(1, 1)
        # variables that i will need
        self.result_of_Hashed_message_Var 
        self.message_Sender_Var
        # all Entries
        self.input_field_1 = tk.Entry(
                                    self,
                                    textvariable='',
                                    justify="left" , 
                                      bd='3px')

        # all Button
        self.certif_button = tk.Button(self,text="Get Certification Autority",command=self.get_certif_by_CA,activebackground='#959595',width=0)
        self.verify_button = tk.Button(self,text="Verify",command=self.verify_existant_key,activebackground='#959595',width=17)
        self.sign_button = tk.Button(self,text='sign the message ', command=self.sign_the_message,activebackground='#959595',width=17)

        self.exit_button = tk.Button(self,text='exit', command=lambda:self.destroy(), width=17)
        
        
        # all labels
        self.Signature_title_lebel = tk.Label(self, text="signature :", justify='left' , width=17  ,underline=17 , wraplength=100 )
        self.Signature_lebel = tk.Label(self, text="signature result", justify='left',bg='#FFFFFF' , width=17  ,underline=17 , wraplength=100 )
        self.Result_validation_label = tk.Label(self, text="???", justify='center',bg='#FFFFFF', width=20  )
        
        # all labels
        self.CA_txt = tk.Text(self, width=17  , height=10, state='disabled' )



                        # grid positions
        self.columnconfigure(0,weight=3 )
        self.columnconfigure(1,weight=1)
        self.rowconfigure(0,weight=2)
        self.rowconfigure(1,weight=1)
        self.rowconfigure(2,weight=1)
        self.rowconfigure(3,weight=1)
        self.rowconfigure(4,weight=5)

                    # positionning the items
        self.input_field_1.grid(column=0,row=0, sticky=tk.W, padx=0, pady=1)
        self.Signature_title_lebel.grid(column=0,row= 1, sticky=tk.W, padx=0, pady=1)
        self.Signature_lebel.grid(column=0,row=2, sticky=tk.W, padx=0, pady=1)
        self.Result_validation_label.grid(column=0 ,row=3, sticky=tk.W, padx=0, pady=1)
        self.CA_txt.grid(column=0,row=4, sticky=tk.W, padx=0, pady=1)

        self.exit_button.grid(column=1,row=0, sticky=tk.W, padx=0, pady=1)
        self.sign_button.grid(column=1,row=1, sticky=tk.W, padx=0, pady=1)
        self.verify_button.grid(column=1,row=3, sticky=tk.W, padx=0, pady=1)
        self.certif_button.grid(column=1,row=4, sticky=tk.W, padx=0, pady=1)
        

                    # fonctions
    def Set_Signature_Sender(self, Sign:str):
        self.signature_Sender_Var.set(Sign[:100])
        
        # self.signature_Sender_label.configure(text=self.signature_Sender_Var.get()[:100])
    def Set_Message_Sender(self, Msg):
        self.message_Sender_Var.set(Msg)
        self.message_Sender_label.configure(text=self.message_Sender_Var.get())

    def hash_string(self): 
        selected = root.Get_selected_hash()
        hash_fonction= getattr(hashlib,selected  )# transformer le string a une fonction de hashage du bib "hashlib"
        self.result_of_Hashed_message_Var.set(hash_fonction(self.message_Sender_Var.get().encode('ascii')).hexdigest())


    def decrypt_string(self): 
      decryptor = PKCS1_OAEP.new(root.Get_Private_Key())
      decrypted = decryptor.decrypt(root.Get_Native_encrypted()).decode('ascii')
      self.result_of_decrypted_signature_Var.set(decrypted)
      self.result_of_decrypted_signature_label.configure(text=self.result_of_decrypted_signature_Var.get())

    def compare_hash(self):
        if str(self.result_of_Hashed_message_Var.get()) == str(self.result_of_decrypted_signature_Var.get()) : 
            self.validation.config(text="valide message", fg='#32cd32')
        else : self.validation.config(text="not valide",fg='#ff0000')


    def RSA_Key_Generation(self,Number):
        self.PrivateKey = RSA.generate(Number)
        # generate RSA Key
        self.PublicKey = self.PrivateKey.publickey()

        # pubKeyPEM = self.PublicKey.exportKey()
        # print(pubKeyPEM.decode('ascii'))

        # privKeyPEM = self.PrivateKey.exportKey()
        # print(privKeyPEM.decode('ascii'))


    def Sign_THE_Hash(self):

        self.RSA_Key_Generation(3072)

        hash_fonction= getattr(hashlib ,self.selected_hash.get() )
        self.hash_Result.set(hash_fonction(self.Input_Message.get().encode()).hexdigest())


        msg = bytes(str(self.hash_Result.get()), encoding='ascii')
        encryptor = PKCS1_OAEP.new(self.PublicKey)
        self.Native_encrypted = encryptor.encrypt(msg)
        cypher_txt = binascii.hexlify(self.Native_encrypted).decode('ascii')
        self.Signature_Result.set(cypher_txt)
        self.Signature_txt['state']= 'normal'
        self.Signature_txt.insert('1.0',cypher_txt)
        self.Signature_txt['state']= 'disabled'
        # self.Signature_txt.config(text=self.Signature_Result.get())

        # print("Encrypted:", binascii.hexlify(encrypted))
        # msg = b'A message for encryption'
        # encryptor = PKCS1_OAEP.new(pubKey)
        # encrypted = encryptor.encrypt(msg)
        # print("Encrypted:", binascii.hexlify(encrypted))


            ######## global fonction ##########

    def get_certif_by_CA(self):
        pass
    def verify_existant_key(self):
        pass
    def sign_the_message(self):
        pass
if __name__ == "__main__":
    
    root = Root()
    root.mainloop()
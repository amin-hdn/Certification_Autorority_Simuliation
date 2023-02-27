import hashlib
import tkinter as tk
from tkinter import ttk

class Root(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Generator")
        self.geometry("600x400")
        self.resizable(1, 1)
        # variables that i will need

        # all Entries
        self.input_field_1 = tk.Entry(
                                    self,
                                    textvariable='',
                                    justify="left" , 
                                      bd='3px')

        # all Button
        self.certif_button = tk.Button(self,text="Get Certification Autority",command='',activebackground='#959595',width=0)
        self.verify_button = tk.Button(self,text="Verify",command='',activebackground='#959595',width=17)
        self.sign_button = tk.Button(self,text='sign the message ', command='',activebackground='#959595',width=17)

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
        


if __name__ == "__main__":
    
    root = Root()
    root.mainloop()
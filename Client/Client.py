# -*- coding: utf-8 -*-
"""
Client aplikacija služi klijentima za povezivanje na TCP server i razmjenu poruka.
Klijenti mogu koristiti privatni ili javni chat.
Dvostrukim klikom na nekog od korisnika iz liste otvara se novi prozor koji
omogućava privatan chat između ta dva korisnika.

|
|
|
"""

from socket import *
from threading import *
from tkinter import *
import tkinter.messagebox


class PrivateWindow:
    """
    Klasa "PrivateWindow" služi za privatan chat između 2 korisnika.
    Dvostrukim klikom na nekog od korisnika u listi online korisnika otvara se ovaj prozor.
    Klijent također ima listu u koju sprema sve trenutno otvorene private prozore ( kako biste sa jednim klijentom mogli komunicirati
    kroz samo 1 privatni prozor).

    |

    :ivar master: Master prozor za ovaj prozor ( zatvaranjem master prozora zatvaraju se i svi privatni prozori. )
    :ivar client: Objekt klase "Client" definirane u istom file-u.
    :ivar windowTitle: Naslov privatnog prozora
    :ivar txtReceive: Tekstualno polje ( za primljene privatne poruke od određenog korisnika )
    :ivar txtInput: Tekstualno polje ( za unos privatne poruke )
    :ivar btnSend: Button(gumb) ( za slanje privatne poruke )
    """


    master = None
    """
    :ivar: master: Master prozor za ovaj prozor ( zatvaranjem master prozora zatvaraju se i svi privatni prozori. )
    :type: tkinter.Tk ili None
    """
    client = None
    """
    :ivar: client: Objekt klase "Client" definirane u istom file-u.
    :type: Client.Client ili None
    """
    windowTitle = None
    """
    :ivar: windowTitle: Naslov privatnog prozora. (oblika: username:ip:port)
    :type: string ili None
    """
    txtReceive = None
    """
    :ivar: txtReceive: Tekstualno polje ( za primljene privatne poruke od određenog korisnika )
    :type: tkinter.Text ili None
    """
    txtInput = None
    """
    :ivar: txtInput: Tekstualno polje ( za unos privatne poruke )
    :type: tkinter.Text ili None
    """
    btnSend = None
    """
    :ivar: btnSend: Button(gumb) ( za slanje privatne poruke )
    :type: tkinter.Button ili None
    """

    def __init__(self, master, client, windowTitle):
        """
        Konstruktor klase PrivateWindow

        :param master: Master prozor za ovaj prozor ( zatvaranjem master prozora zatvaraju se i svi privatni prozori. )
        :type master: tkinter.Tk ili None
        :param client: Objekt klase "Client" definirane u istom file-u.
        :type client: Client.Client ili None
        :param windowTitle: Naslov privatnog prozora
        :type windowTitle: string
        :return: None
        :rtype: None
        """
        self.master = master
        self.client = client
        self.windowTitle = windowTitle

        self.root = Toplevel(self.master)
        self.root.title(self.windowTitle)
        self.root.protocol("WM_DELETE_WINDOW", self.onClosing)

        # --------------- Kreiranje private window GUI-a -----------------------------------
        self.txtReceive = Text(self.root, height=10)
        self.txtInput = Text(self.root, height=5)
        self.btnSend = Button(self.root,text="Send", command=self.btnSend_click)
        self.txtReceive.config(state=DISABLED)

        # --------------- Crtanje private window prozora ------------------------------------
        self.txtReceive.grid(row=0, column=0, columnspan=2, sticky="NESW")
        self.txtInput.grid(row=1, column=0, sticky="NESW")
        self.btnSend.grid(row=1, column=1, sticky="NESW")

        self.icon = PhotoImage(file='chatIcon.png')
        self.root.tk.call('wm', 'iconphoto', self.root._w, self.icon)


    def btnSend_click(self):
        """
        Metoda koja se poziva klikom na "btnSend" gumb unutar privatnog prozora.
        Ako tekst nije unešen u tekstualno polje "txtInput" metoda će jednostavno return-ati,
        u suprotnom pokušava poslati privatnu poruku.

        :return: None
        :rtype: None
        :raise: socket.error
        """
        if not self.txtInput.get(1.0, END):
            return
        data = str("privateMessage|" + self.windowTitle + "|" + self.client.username +":"+ self.client.addr + "|" + self.txtInput.get(1.0, END)).encode()
        try:
            self.client.sock.send(data)
        except error as e:
            tkinter.messagebox.showinfo("Error", str(e))
        self.appendMsg("You say: " + self.txtInput.get(1.0, END))
        self.txtInput.delete(1.0, END)

    def appendMsg(self, msg):
        """
        Metoda koja služi za dodavanje teksta u "txtReceive" tekstualno polje.

        :param msg: Poruka koju želimo dodati u tekstualno polje.
        :type msg: string ili None
        :return: None
        :rtype: None
        """
        self.txtReceive.config(state=NORMAL)
        self.txtReceive.insert(END, msg)
        self.txtReceive.config(state=DISABLED)

    def onClosing(self):
        """
        Metoda koja se poziva kada klijent zatvori privatni prozor (kada pritisne "X" u gornjem desnom kutu).
        Uništava privatni prozor, i izbacuje ga iz klijentove liste otvorenih privatnih chat prozora.

        :return: None
        :rtype: None
        """
        for w in self.client.privateChatWindows:
            if self == w:
                self.client.privateChatWindows.remove(self)
        self.root.destroy()

class Client:
    """
    Klasa "Client" omogućava korisniku unos korisničkog imena i povezivanja na TCP server.
    Ako je povezivanje uspjelo korisnik može pisati javne poruke, i otvarati prozore za privatan chat sa ostalim
    online klijentima.

    |
    |

    :ivar host: Ip adresa servera na koji se klijent povezuje
    :ivar port: Broj porta servera na koji se klijent povezuje
    :ivar privateChatWindows: Lista trenutno otvorenih privatnih prozora
    :ivar receiveDataFromServerThread: Nit(Thread, dretva) za primanje podataka od servera
    :ivar sock: Klijentov socket
    :ivar username: Korisničko ime klijenta
    :ivar addr: Adresa klijenta

    |
    |
    """
    host = None
    """
    :ivar: host: Ip adresa servera
    :type: string
    """
    port = None
    """
    :ivar: port: Broj porta servera na koji se klijent povezuje.
    :type: int
    """
    privateChatWindows = None
    """
    :ivar: privateChatWindows: Lista trenutno otvorenih prozora za privatni chat.
    :type: List ili None
    """
    receiveDataFromServerThread = None
    """
    :ivar: receiveDataFromServerThread: Nit(Thread, dretva) koja služi za primanje podataka od servera.
    :type: Thread ili None
    """
    sock = None
    """
    :ivar: sock: Klijentov socket
    :type: socket(AF_INET, SOCK_STREAM)
    """
    username = None
    """
    :ivar: username: Korisničko ime klijenta
    :type: string

    |
    |
    |
    """
    addr = None
    """
    :ivar: addr: Ip adresa i port klijenta
    :type: tuple(string, int) --- tuple(ip, port)
    """

    def __init__(self, host, port):
        """
        Konstruktor klase Client
        Kreira grafičko sučelje, te povezuje klijenta sa serverom ako je to moguće.

        :param host: Ip servera
        :type host: string
        :param port: Port servera
        :type port: int
        :return: None
        :rtype: None
        |
        |
        """
        # inicijalizacija članova klase
        self.host = host
        self.port = port
        self.privateChatWindows = []
        self.receiveDataFromServerThread = None
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.username = ""
        self.addr = ""

        self.root = Tk()
        self.root.title("Client")
        self.root.protocol("WM_DELETE_WINDOW", self.onClosing)
        # ------------------ Kreiranje grafickog sucelja --------------------------
        self.txtReceive = Text(self.root)
        self.txtInput = Text(self.root, height=10)
        self.lblUsername = Label(self.root, text="Username: ")
        self.txtUsername = Entry(self.root)
        self.btnConnect = Button(self.root, text="Connect", command=self.btnConnect_click)
        self.btnSend = Button(self.root, text="Send", command=self.btnSend_click)
        self.clientsListBox = Listbox(self.root, height=25)
        self.clientsListScroll = Scrollbar(self.root, orient=VERTICAL)
        self.clientsListScroll.configure(command=self.clientsListBox.yview)
        self.clientsListBox.configure(yscrollcommand=self.clientsListScroll.set)
        self.clientsListBox.bind("<Double-Button-1>", self.clientsListBoxEntryOnDblClick)

        # ------------- Crtanje grafičkog sučelja -----------------
        self.lblUsername.grid(row=0, column=0, sticky="E")
        self.txtUsername.grid(row=0, column=1, sticky="W")
        self.btnConnect.grid(row=0, column=2, sticky="W")
        self.txtReceive.grid(row=1, column=0, columnspan=3, rowspan=3, sticky="NESW")
        self.clientsListBox.grid(row=1, column=3, rowspan=2, sticky="NESW")
        self.clientsListScroll.grid(row=1, column=4, rowspan=2, sticky="NESW")
        self.txtInput.grid(row=4, column=0, columnspan=3, sticky="NESW")
        self.btnSend.grid(row=4, column=3, rowspan=2,columnspan=2, sticky="NESW")

        self.icon = PhotoImage(file='chatIcon.png')
        self.root.tk.call('wm', 'iconphoto', self.root._w, self.icon)

        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(3, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.columnconfigure(2, weight=1)
        self.root.columnconfigure(3, weight=1)
        self.root.columnconfigure(4, weight=1)

        self.txtReceive.config(state=DISABLED)


        self.root.mainloop()

    def btnSend_click(self):
        """
        Metoda koja se poziva klikom na "btnSend" gumb unutar prozora za javni chat.
        Ako nije unešen nikakav text, metoda će return-ati, u suprotnom pokušava
        poslati unešeni tekst kao javnu poruku.

        :return: None
        :rtype: None
        :raise: socket.error
        """
        if not self.txtInput.get(1.0, END):
            return
        data = str("publicMessage|" + self.txtUsername.get()+" says: " + self.txtInput.get(1.0, END)).encode()
        try:
            self.sock.send(data)
        except error as e:
            tkinter.messagebox.showinfo("Error", str(e))
        self.txtInput.delete(1.0, END)

    def btnConnect_click(self):
        """
        Metoda koja se poziva klikom na "btnConnect" gumb unutar prozora za javni chat.
        Metoda će return-ati ako nije unešeno korisničko ime, u suprotnom pokušava povezati klijenta
        sa serverom.
        Ako je povezivanje uspješno serveru se šalje "clientConnected" paket koji sadrži više podataka o novom klijentu
        radi ažuriranja liste klijenata, te se pokreće klijentova nit za primanje podataka od servera(receiveDataFromServerThread).

        :return: None
        :rtype: None
        :raise: socket.error
        """
        if not self.txtUsername.get():
            return
        self.username = self.txtUsername.get()
        try:
            self.sock.connect((self.host, self.port))
        except error as e:
            tkinter.messagebox.showinfo("Error", str(e))
            return
        self.appendMsg("Povezivanje sa serverom uspjesno!\n")
        # start receiving data from server
        self.receiveDataFromServerThread = Thread(target=self.recvFromServer)
        self.receiveDataFromServerThread.daemon = True
        self.receiveDataFromServerThread.start()
        try:
            addr = self.sock.getsockname()
            self.addr = str(addr[0]) + ":" + str(addr[1])
            connMsg = str("clientConnected|" + str(self.username) +":"+self.addr)
            self.sock.send(connMsg.encode())
        except error as e:
            tkinter.messagebox.showinfo("Error", str(e))

    def clientsListBoxEntryOnDblClick(self, event):
        """
        Metoda koja se poziva dvostrukim klikom na nekog od online klijenata iz liste online klijenata.
        Metoda provjerava je li već otvoren privatni prozor sa odabranim klijentom, te ako jeste stavi fokus na taj prozor,
        a ako nije otvara novi prozor za privatni chat sa odabranim klijentom i sprema taj prozor u listu privatnih prozora.

        :param event: Event
        :type event: Event
        :return: None
        :rtype: None
        """
        widget = event.widget
        selected = widget.curselection()
        selectedValue = str(widget.get(selected[0]))
        #pw = PrivateWindow(self.root, self, selectedValue)
        for privateWindow in self.privateChatWindows:
            if selectedValue == privateWindow.windowTitle:
                return
        pw = PrivateWindow(self.root, self, selectedValue)
        self.privateChatWindows.append(pw)

    def handlePacket(self, msg):
        """
        Metoda koja obrađuje paket primljen od strane servera.

        Primljeni paket je string oblika: tipPaketa|tekst korisničke poruke

        U slučaju privatne poruke paket ima oblik: tipPaketa|podatciOIzvorištu|podatciOOdredištu|tekst korisničke poruke

        Primljena poruka rastavlja se na svako pojavljivanje znaka '|', i tako se dobiva
        lista stringova.

        npr. poruka = privateMessage|zeljko:127.0.0.1:5678|mario:127.0.0.1:8765|Tekst korisničke poruke
        =>
        rastavljenaPoruka = ["privateMessage", "zeljko:127.0.0.1:5678", "mario:127.0.0.1:8765", "Tekst korisničke poruke"]

        U rastavljenoj poruci (u listi) na prvom mjestu (indeksu 0) nalazi se tip paketa.
        Na drugom mjestu (index 1) nalaze se podatci o izvorištu, a na
        trećem mjestu (index 2) nalaze se podatci o odredištu.
        Svi ostali elementi liste su korisnička poruka. (indeksi od 3 pa nadalje)

        Poruka se zatim ponovno sastavlja ali bez podataka o tipu paketa, izvorištu i odredištu, i to opet
        na svako pojavljivanje znaka '|'. (jer je korisnik mogao unijeti znak '|' unutar svoje poruke)

        sastavljenaPoruka = '|'.join(rastavljenaPoruka[3:]) ==> spoji rastavljenu poruku znakom '|', počevši od
        indeksa broj 3 pa nadalje.

        :param msg: Primljeni paket u obliku stringa
        :type msg: string
        :return: None
        :rtype: None
        """
        data = str.split(msg, '|')
        if data[0] == "updateListBox":
            users = '|'.join(data[1:])
            self.updateListBox(str(users))
        elif data[0] == "publicMessage":
            d = '|'.join(data[1:])
            self.appendMsg(str(d))
        elif data[0] == "privateMessage":
            sender = data[1] # sender data
            senderUsername = str.split(sender, ':')[0]
            d = '|'.join(data[2:]) # msg
            for privateWindow in self.privateChatWindows:
                if privateWindow.windowTitle == sender:
                    privateWindow.appendMsg(senderUsername + " says: " + str(d))
                    return
            pw = PrivateWindow(self.root, self, sender)
            pw.appendMsg(str(d))
            self.privateChatWindows.append(pw)
        else:
            d = '|'.join(data)
            self.appendMsg(str(d))

    def updateListBox(self, users):
        """
        Metoda koja služi za ažuriranje liste online klijenata.

        :param users: Lista online klijenata primljena od servera u obliku stringa.
        :type users: string
        :return: None
        :rtype: None
        """
        self.clientsListBox.delete(0, END)
        u = str.split(users, '|')
        addr = self.sock.getsockname()
        for user in u:
            if user != self.username +":"+ str(addr[0]) +":"+ str(addr[1]):
                self.clientsListBox.insert(END, user)

    def recvFromServer(self):
        """
        Metoda koja prihvaća podatke od servera i poziva "handlePacket" metodu ako ima podataka.

        :return: None
        :rtype: None
        """
        while True:
            data = self.sock.recv(2048)
            if not data:
                break
            msg = str(data.decode())
            self.handlePacket(msg)

    def appendMsg(self, msg):
        """
        Metoda koja služi za dodavanje teksta u "txtReceive" tekstualno polje (poruke javnog chat-a).

        :param msg: Poruka koju treba dodati.
        :type msg: string
        :return: None
        :rtype: None
        """
        self.txtReceive.config(state=NORMAL)
        self.txtReceive.insert(END, msg)
        self.txtReceive.config(state=DISABLED)

    def onClosing(self):
        """
        Metoda koja se poziva prilikom zatvaranja aplikacije. (klikom na "X" gumb u gornjem desnom kutu.)

        :return: None
        :rtype: None
        """
        self.root.destroy()

def main():
    """
    Main metoda Client skripte.

    :return: None
    :rtype: None
    """
    client = Client("127.0.0.1", 6666)



if __name__ == "__main__":
    main()
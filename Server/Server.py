# -*- coding: utf-8 -*-
"""
Server aplikacija služi za pokretanje TCP servera na određenom portu i ip adresi.
Server čeka i prihvaća nadolazeće konekcije od strane klijenata.
Trenutno spojene klijente sprema u listu.

|
|
|
"""

from socket import * # za rad sa socketima
from threading import * # za rad sa nitima (Threads)
from tkinter import * # biblioteka za GUI
import tkinter.messagebox



class Client:
    """
    **Klasa "Client" služi serveru kao model za rukovanje klijentima.
    Kada server prihvati klijenta, kreira novi objekt klase "Client" i sprema ga u
    listu spojenih klijenata.**

    |
    |
    :ivar sock: Klijentov socket
    :ivar addr: Klijentova adresa
    :ivar username: Korisničko ime klijenta
    :ivar handleClientThread: Nit za rukovanje klijentom

    |
    |
    """

    sock = None
    """
    :ivar: sock: Klijentov socket
    :type: sock: socket(AF_INET, SOCK_STREAM)
    """
    addr = None
    """
    :ivar: addr: Klijentova adresa tuple(ip, port)
    :type: addr: tuple(string, int)
    """
    username = ""
    """
    :ivar: username: Korisničko ime klijenta - type: string
    :type: username: string

    |
    |
    """
    handleClientThread = None
    """
    :ivar: handleClientThread: Nit(Thread) za rukovanje klijentom - type: Thread ili None
    :type: Thread ili None
    """
    def __init__(self, sock, addr):
        """
        **Konstruktor klase "Client":**

        **__init__(self, sock, addr)**


        :param sock: Socket prihvaćenog klijenta
        :type sock: socket
        :param addr: Adresa prihvaćenog klijenta
        :type addr: tuple(ip, port)
        :return: None
        :rtype: None
        """
        self.sock = sock
        self.addr = addr
        self.username = ""
        self.handleClientThread = None

class Server():
    """
    **Klasa "Server"
    Kreira grafičko sučelje, pokreće server na ip adresi i portu,
    te obrađuje podatke koje primi od klijenata.**

    |
    |
    :ivar host: Ip adresa servera
    :ivar port: Port servera
    :ivar listener: Listener socket
    :ivar clients: Lista klijenata
    :ivar acceptClientsThread: Nit za prihvaćanje klijenata
    :ivar txtReceive: Tekstualno polje (za poruke sa javnog chat-a)
    :ivar txtInput: Tekstualno polje (za unos poruke za javni chat)
    :ivar btnSend: Button(tipka) za slanje poruke u javnom chat-u
    :ivar clientsListBox: ListBox koji prikazuje online korisnike
    :ivar clientsListScroll: Scrollbar za kretanje kroz listu online korisnika

    |
    |
    """

    host = ""
    """
    :ivar: host: Ip adresa servera
    :type: string
    """
    port = 0
    """
    :ivar: port: Port servera
    :type: int
    """
    listener = None
    """
    :ivar: listener: Socket koji čeka i prihvaća konekcije
    :type: socket(AF_INET, SOCK_STREAM)
    """
    clients = []
    """
    :ivar: clients: Lista trenutno povezanih klijenata
    :type: List
    """
    acceptClientsThread = None
    """
    :ivar: acceptClientsThread: Nit unutar koje listener socket prihvaća konekcije u beskonačnoj petlji.
    :type: Thread ili None
    """
    txtReceive = None
    """
    :ivar: txtReceive: Tekstualno polje (za poruke sa javnog chat-a)
    :type: tkinter.Text ili None
    """
    txtInput = None
    """
    :ivar: txtInput: Tekstualno polje (za unos poruke za javni chat)
    :type: tkinter.Text ili None
    """
    btnSend = None
    """
    :ivar: btnSend: Button(tipka) za slanje poruke u javni chat
    :type: tkinter.Button ili None
    """
    clientsListBox = None
    """
    :ivar: clientsListBox: ListBox za prikaz online korisnika
    :type: tkinter.Listbox ili None
    """
    clientsListScroll = None
    """
    :ivar: clientsListScroll: Scrollbar za kretanje kroz listu online korisnika
    :type: tkinter.Scrollbar ili None
    """

    def __init__(self, host, port):
        """
        **Konstruktor klase "Server"**

        **__init__(self, host, port)**

        :param host: Adresa servera
        :type host: string
        :param port: Port servera
        :type port: int
        :return: None
        :rtype: None
        |
        |
        """
        self.root = Tk()
        self.root.title("Server")
        self.root.protocol("WM_DELETE_WINDOW", self.onClosing)

        self.host = host
        self.port = port

        # ---------- Kreiranje GUI-a ----------------------
        self.txtReceive = Text(self.root, bd="2")
        self.txtInput = Text(self.root, height=10, bd="2")
        self.btnSend = Button(self.root, text="Send", bd="2", command=self.btnSend_click)
        self.clientsListBox = Listbox(self.root,height=25)
        self.clientsListScroll = Scrollbar(self.root, orient=VERTICAL)
        self.clientsListScroll.configure(command=self.clientsListBox.yview)
        self.clientsListBox.configure(yscrollcommand=self.clientsListScroll.set)

        # ----------- Crtanje GUI-a -----------------------------------------------
        self.txtReceive.grid(row=0, column=0, columnspan=3, rowspan=3, sticky="NESW")
        self.clientsListBox.grid(row=0, column=3, rowspan=2, sticky="NESW")
        self.clientsListScroll.grid(row=0, column=4, rowspan=2, sticky="NESW")
        self.txtInput.grid(row=3, column=0, columnspan=3, sticky="NESW")
        self.btnSend.grid(row=3, column=3, rowspan=2,columnspan=2, sticky="NESW")

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

        self.txtReceive.config(state=DISABLED) # tekstualno polje za primljene poruke read-only
        # ------------------------ Kreiranje GUI-a END ---------------------------------------------------------

        # ------------------------ Pokreni server ---------------------------------------------------------
        self.listener = socket(AF_INET, SOCK_STREAM)
        self.listener.bind((self.host, self.port))
        self.listener.listen(10)
        self.appendMsg("Server pokrenut na: " + str(self.host) + ":" + str(self.port) + "\n")
        # ---------------------- Kreni sa prihvatanjem klijenata ---------------------------------------------
        self.acceptClientsThread = Thread(target=self.acceptClients)
        self.acceptClientsThread.daemon = True
        self.acceptClientsThread.start()
        self.appendMsg("Cekam na nadolazece konekcije...\n")
        self.root.mainloop()

    def broadcast(self, msg):
        """
        Metoda koja služi za serveru za odašiljanje poruke svim trenutno povezanim klijentima.


        :param msg: Poruka koju želimo poslati
        :type msg: string
        :return: None
        :rtype: None
        :raise: socket.error
        """
        data = str(msg).encode()
        for cl in self.clients:
            try:
                cl.sock.send(data)
            except error as e:
                #tkinter.messagebox.showinfo("Error", str(e))
                pass

    def acceptClients(self):
        """
        Metoda se pokreće u posebnoj niti (Thread) unutar konstruktora, stoga server može obrađivati podatke
        i prihvaćati konekcije odjednom.
        Metoda vrti beskonačnu petlju i prihvaća konekcije prema serveru ako ih ima, i za svakog prihvaćenog klijenta
        kreira novi objekt klase "Client", pokreće nit za rukovanje tim korisnikom(handleClientThread), te dodaje
        objekt u listu trenutno povezanih klijenata.

        :param: None
        :return: None
        :rtype: None
        """
        while True:
            conn, addr = self.listener.accept()
            if conn:
                newClient = Client(conn, addr) # kreiranje novog klijenta
                newClient.handleClientThread = Thread(target=self.handleClient, args=(newClient.sock,newClient.addr))
                newClient.handleClientThread.daemon = True
                newClient.handleClientThread.start()
                self.clients.append(newClient)
                #self.updateListBox()
                #self.sendListBoxUpdateRequest()
        self.listener.close()

    def handleClient(self, conn, addr):
        """
        Prihvaća podatke od klijenta ako ih ima,
        te ih u obliku stringa predaje funkciji handlePacket koja nadalje obrađuje podatkovni paket.

        :param conn: Klijentov socket
        :type conn: socket(AF_INET, SOCK_STREAM)
        :param addr: Klijentova adresa
        :type addr: tuple(string, ip) npr. ("127.0.0.1", 6666)
        :return: None
        :rtype: None
        """
        while True:
            try:
                data = conn.recv(2048)
            except error as e:
                #tkinter.messagebox.showinfo("Error", str(e))
                break
            if not data:
                break
            msg = str(data.decode())
            # ----------------- handle packet -------------------
            self.handlePacket(msg)
        self.appendMsg("Klijent je napustio chat...\n")
        # izbaci klijena koji je napustio chat iz liste klijenata
        for cl in self.clients:
            if cl.sock == conn:
                self.clients.remove(cl)
        # ---- update-aj listbox koji prikazuje trenutno povezane klijente
        self.updateListBox()
        # ---- posalji klijentima zahtjev za update liste klijenata
        self.sendListBoxUpdateRequest()
        conn.close()

    def btnSend_click(self):
        """
        Metoda koja se poziva kada se klikne na button "btnSend" ( koji sluzi za slanje poruka u javnom chat-u )
        Ako nije unešen nikakav tekst u "txtInput" polje metoda jednostavno return-a,
        u suprotnom server broadcast-a unešenu poruku svim online klijentima.

        :return: None
        :rtype: None
        """
        if not self.txtInput.get(1.0, END):
            return
        msg = self.txtInput.get(1.0, END)
        self.broadcast("Server says: " + msg)
        self.txtInput.delete(1.0, END)


    def handlePacket(self, msg):
        """
        Metoda koja služi serveru za obrađivanje podatkovih paketa primljenih od strane klijenata.
        Server razlikuje 5 tipova paketa:

        1. clientConnected - za obradu tek povezanih klijenata ( dodavanje u listu online korisnika i sl.)

        2. clientDisconnected - za obradu klijenata koji su napustili chat (brisanje iz liste korisnika, zatvaranje klijentovog
        socketa i sl.)

        3. publicMessage - za obradu javnih poruka (proslijeđivanje javne poruke primljene od nekog klijenta
        svim ostalim online klijentima)

        4. privateMessage - za obradu privatnih poruka (proslijeđivanje privatne poruke od jednog klijenta ka drugom)

        5. error - za obradu pogrešaka (server klijentu javlja da je došlo do neke pogreške. npr. Korisničko ime je zauzeto i sl.)

        Primljena poruka je oblika: tipPaketa|Klijentova poruka serveru.

        Privatna poruka je oblika: tipPaketa|podatciOPošiljatelju|podatciOPrimatelju|Klijentova poruka.

        Metoda rastavlja primljenu poruku na svako pojavljivanje znaka '|', te tako dobiva listu
        stringova.

        npr. poruka = privateMessage|zeljko:127.0.0.1:5678|mario:127.0.0.1:8765|Ovo je moja poruka
            =>
            rastavljenaPoruka = ["privateMessage", "zeljko:127.0.0.1:5678", "mario:127.0.0.1:8765", "Ovo je moja poruka"]

        U rastavljenoj poruci na prvom mjestu (indexu 0) uvijek se nalazi tip poruke.

        npr. print(rastavljenaPoruka[0]) ispisati ce string "privateMessage"

        Nakon što server odredi tip paketa, ponovno spaja rastavljenu poruku sa znakom '|' (jer korisnik unutar svoje
        poruke može unijeti znak '|').
        Server iz ponovno sastavljene poruke odbacuje tip paketa i podatke o odredištu i izvorištu,
        i ostane mu samo tekst koji je user unijeo, i u ovoj situaciji server zna što treba napraviti sa danom porukom.

        sastavljenaPoruka = '|'.join(rastavljenaPoruka[3:]) --> spoji sve stringove iz liste rastavljenih poruka, počevši
        od 3. indexa  i poveži ih znakom '|'.

        :param msg: Primljeni podatci u obliku stringa
        :type msg: string
        :return: None
        :rtype: None
        """
        data = str.split(msg, '|')
        if data[0] == "clientConnected":
            d = '|'.join(data[1:])
            clientData = str.split(d, ':')
            username = clientData[0]
            ipAddr = clientData[1]
            port = clientData[2]
            self.appendMsg(username + " connected from: " + str(ipAddr) + str(port) + "\n")
            for client in self.clients:
                if str(client.addr[0]) == ipAddr and str(client.addr[1]) == port:
                    client.username = username
            self.updateListBox()
            self.sendListBoxUpdateRequest()
        elif data[0] == "clientDisconnected":
            d = '|'.join(data[1:])
        elif data[0] == "publicMessage":
            d = '|'.join(data[1:])
            self.appendMsg(str(d))
            self.broadcast("publicMessage|" + str(d))
        elif data[0] == "privateMessage":
            dst = data[1]
            sender = data[2]
            dstData = str.split(dst, ':')
            dstUsername = dstData[0]
            dstIp = dstData[1]
            dstPort = dstData[2]
            senderData = str.split(sender, ':')
            senderUsername = senderData[0]
            d = '|'.join(data[3:])
            for cl in self.clients:
                if cl.username == dstUsername and str(cl.addr[0]) == dstIp and str(cl.addr[1]) == dstPort:
                    data = str.encode("privateMessage|" + str(sender) + "|" + str(d))
                    cl.sock.send(data)
        elif data[0] == "error":
            d = '|'.join(data[1:])


    def updateListBox(self):
        """
        Metoda koja služi za ažuriranje liste online klijenata.
        Ova metoda se poziva kada server prihvati novog klijenta, ili kada
        neki od klijenata napusti chat.

        :return: None
        :rtype: None
        """
        self.clientsListBox.delete(0, END)
        for cl in self.clients:
            if cl.sock != self.listener:
                self.clientsListBox.insert(END,cl.username +":"+  cl.addr[0] + ":" + str(cl.addr[1]))

    def sendListBoxUpdateRequest(self):
        """
        Metoda kojom server šalje klijentima poruku da je došlo do izmjene liste klijenata.
        Server šalje klijentima poruku oblika: updateListBox|username1:ip1:port1|username2:ip2:port2|usernameN:ipN:portN
        Kada klijent primi ovu poruku, on će ju rastaviti na svako pojavljivanje znaka '|', i tako
        će dobiti ažuriranu listu trenutno online korisnika.

        :return: None
        :rtype: None
        """
        users = '|'.join(str(x.username + ":"+ x.addr[0] +":"+ str(x.addr[1])) for x in self.clients)
        reqString = "updateListBox|" + users
        self.broadcast(reqString)

    def onClosing(self):
        """
        Metoda koja se poziva kada korisnik zatvori aplikaciju. (Pritisak na "X" gumb u gornjem desnom kutu)"

        :return: None
        :rtype: None
        """
        self.root.destroy()


    def appendMsg(self, msg):
        """
        Metoda koja služi za dodavanje tekta u "txtReceive" tekstualno polje.

        :param msg: Tekst koji želimo dodati u "txtReceive" tekstualno polje.
        :type: string
        :return: None
        :rtype: None
        """
        self.txtReceive.config(state=NORMAL)
        self.txtReceive.insert(END, msg)
        self.txtReceive.config(state=DISABLED)

def main():
    """
    Main metoda Server skripte.

    :return: None
    :rtype: None
    """
    server = Server("127.0.0.1", 6666)

if __name__ == "__main__":
    main()
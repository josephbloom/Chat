#!/usr/bin/python

"""
====== To do ======
	- KeepAlive
	- needs better method of detecting IP address
	- Label (?) for receiving view
		- copy-able text?
	- clear receive view
	- SAFE removal and reading of extra backslashes
	- Produce .txt of conversation
	- Encryption methods
	- password

====== Check for ======
	- connecting on a port that's already being used, already listening
	for something else (like port 80), etc.
	- Sending messages too fast causes error. Probably fix with blocking.
"""


from Tkinter import *
# import tkFileDialog
import ttk
import threading
import socket
import Queue
from platform import system

c = ''
mainevent = threading.Event()
stoplistenthread = threading.Event()
serverison = threading.Event()
connectison = threading.Event()
connect_event = threading.Event()

global connection
root = Tk()
ReceivingQueue = Queue.Queue()
listenorconnect = StringVar()

# placeholder values for global calls

#################################################
############	 LISTENING		#################
#################################################

# def get_ip_address():
getmyIP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
getmyIP.connect(("8.8.8.8", 80))
myIP = getmyIP.getsockname()[0]
print "my IP address is "+str(myIP)
# myIP = "192.168.1.111"
myport=8081

def startlisten():
	# Create a TCP/IP socket to listen on
	global server
	global mainevent
	global myport
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# Prevent from "address already in use" upon server restart
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Bind the socket to myport on all interfaces
	server_address = (myIP, myport)
	print '\nstarting up on %s port %s' % server_address
	ReceivingQueue.put(('starting up on %s port %s' % server_address,"blue"))
	try:
		server.bind(server_address)
	except:
		# connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
		# connection.close()
		print "--- Server stopped. Couldn't establish address. ---"
		ReceivingQueue.put(("*** Server stopped. Couldn't establish address. ***","red"))
		server.close()
		mainevent.set()
		startbuttonon()
		
		quit()
	mainevent.set()

	server.listen(5) # Listen for connections
	global connection

	serverison.set()
	ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: LISTENING")',"guiupdate"))
	print 'serverison true'
	print "Waiting for incoming connection..."
	ReceivingQueue.put(("Waiting for incoming connection...","blue"))
	connection, client_address = server.accept() # Wait for one incoming connection
	if stoplistenthread.is_set() == True:
		print "error: stoplistenthread is set to true"
		server.close()
		stoplistenthread.clear()
		serverison.clear()
		ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
		return
	connect_event.set()
	ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: CONNECTED")',"guiupdate"))
	print "\nconnection from ", connection.getpeername()
	ReceivingQueue.put(("connection from "+str(connection.getpeername()),"blue"))

	while True:
		print "waiting to receive"
		data = connection.recv(4096) or stoplistenthread.wait() # Waiting to receive something
		# print "data is ",data
		if type(data) == str:
			# print "Data is a string"
			if data[0] == '1':
				print "Received:",repr(data[1:])
				ReceivingQueue.put(("Received: "+str(cleanmessage(data[1:])),"black"))
			if data[0] == '0':
				connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
				connection.close()
				server.close()
				serverison.clear()
				connect_event.clear()
				stoplistenthread.clear()
				ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
				startbuttonon()
				print "--- Connection closed from other side: Quit signal. ---"
				ReceivingQueue.put(("--- Connection closed from other side: Quit signal. ---","blue"))
				break
			if data == '':
				connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
				connection.close()
				server.close()
				serverison.clear()
				connect_event.clear()
				stoplistenthread.clear()
				ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
				startbuttonon()
				print "--- Connection closed from other side: No signal. ---"
				ReceivingQueue.put(("--- Connection closed from other side: No signal. ---","blue"))
				break
		elif type(data) == bool and data == True:
			connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
			connection.close()
			serverison.clear()
			server.close()
			connect_event.clear()
			ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
			startbuttonon()
			print "--- Connection closed from here. ---"
			ReceivingQueue.put(("--- Connection closed from here. ---","blue"))
			stoplistenthread.clear()
			break
		else:
			print "Something unexpected happened. Connection stopped:"
			print data
			ReceivingQueue.put(("Something unexpected happened. Connection stopped:\n"+str(data),"red"))
			break

def startlistenthread():
	if not 'listenthread' in [i.name for i in threading.enumerate()]:
		startbuttonoff()
		global listenthread
		global myport
		if len(PortEntry.get()) < 6 and PortEntry.get().isdigit():
			myport = int(PortEntry.get())
		else:
			ReceivingQueue.put(("--- Port must be a whole, positive integer. ---","red"))
			startbuttonoff()
			return
		listenthread = threading.Thread(target=startlisten,name="listenthread")
		print 'thread defined'
		listenthread.start()
		print 'thread started'
	else:
		print "\nServer already on.\n"

def closeconnection():
	global connection
	global listenthread
	global receivethread
	activethreads = [i.name for i in threading.enumerate()]
	if 'listenthread' in activethreads or 'receivethread' in activethreads:
		ReceivingQueue.put(("Closing...","blue"))
		if connect_event.is_set() == True:
			connection.send('0')
		stoplistenthread.set()
		fakeconnect()
		print "joining thread"
		if 'listenthread' in activethreads:
			print activethreads
			listenthread.join()
			print "listenthread joined"
		if 'receivethread' in activethreads:
			print activethreads
			connectionevent.set()
			connection.send('0')
			receivethread.join()
			print "receivethread joined"
		try:
			server.close()
		except:
			pass
		stoplistenthread.clear()
		print "\nStopped listening. Any connections are closed.\n"
		startbuttonon()
		ReceivingQueue.put(("Closed successfully.","blue"))
	else:
		print "\nServer already off.\n"
		ReceivingQueue.put(("Already not listening. No connection to close.","red"))

#################################################
############		CONNECTING		#############
#################################################

targetaddress = (myIP,myport)
connectionevent = threading.Event()

def receivemessage():
    global connectionevent
    global connection
    global targetaddress
    while True:
        print 'waiting on data'
        data = connection.recv(1024) or connectionevent.wait()
        # data = s.recv(1024)
        if type(data) == str:
            print 'data is str'
            if data == '' or data[0] == '0':
				connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
				connection.close()
				connectionevent.clear()
				connectison.clear()
				stoplistenthread.clear()
				ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
				startbuttonon()
				print "--- connection closed by other side ---"
				ReceivingQueue.put(("--- Connection closed by other side ---", "blue"))
				break
            elif data[0] == '1':
				print "Received:",data[1:]
				ReceivingQueue.put(("Received: "+str(cleanmessage(data[1:])),"black"))
            else:
				print "Unexpected data:\n",data
				ReceivingQueue.put(("--- Unexpected data ---\n"+str(data),"red"))
				break
        if type(data) == bool and data == True:
			print 'data is bool'
			print data
			connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
			connection.close()
			connectionevent.clear()
			connectison.clear()
			stoplistenthread.clear()
			ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: OFF")',"guiupdate"))
			startbuttonon()
			print "--- connection closed by you ---"
			ReceivingQueue.put(("--- Connection closed by you ---","blue"))
			break

def makeconnection():
	print "make connection started"
	global targetaddress
	global connection
	global receivethread
	global myport
	connection=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print "about to try to connect"
	# ReceivingQueue.put(("Trying to connect...","blue"))
	print "trying to connect to %s on port %s" % targetaddress
	ReceivingQueue.put(("Trying to connect to %s on port %s..." % targetaddress,"blue"))
	try:
		connection.connect(targetaddress)
	except socket.error as err:
		startbuttonon()
		print "\nSocket not open. Could not be reached.\n"
		ReceivingQueue.put(("Socket not open. Could not reach listener.","red"))
		# print err
		return
	print "Listening on port",connection.getsockname()
	ReceivingQueue.put(('ConnectionLabel.configure(text="Connection: CONNECTED")',"guiupdate"))
	ReceivingQueue.put(("Listening on port "+str(connection.getsockname()),"blue"))
	myport = connection.getsockname()[1]
	receivethread = threading.Thread(target=receivemessage, name="receivethread")
	connectison.set()
	receivethread.start()

def startconnectthread():
	if 'receivethread' in [i.name for i in threading.enumerate()]:
		print "Connection already established."
	else:
		global targetaddress
		if not IPaddressEntry.get() == "":
			print "IPaddressEntry isn't empty"
			print "Has "+str(IPaddressEntry.get())
			targetaddress = (str(IPaddressEntry.get()),int(PortEntry.get()))
			print "targetaddress changed to "+str(targetaddress)
		startbuttonoff()
		makeconnection()

#################################################
#################################################
#################################################


def fakeconnect():
	fakeaddress = (str(myIP), int(myport))
	print myIP
	print myport
	print fakeaddress
	if 'listenthread' in [i.name for i in threading.enumerate()] and connect_event.is_set() == False:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(fakeaddress)
		# if connect_event.is_set() == True:
		# 	connection.send('0')
		# else:
		# 	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# 	s.connect(fakeaddress)
	# if 'receivethread' in [i.name for i in threading.enumerate()]:
	# 	connection.send('0')
	# server.close()
	# server.close()

def helpmenu():
	print "\nCommand Menu:"
	print "(-a) Begin listening."
	print "(-cc) Stop listening."
	# print "(r) Reset connections."
	print "(-s) Active threads."
	print "(-h) This menu."
	print "(-q) Quit."
	print

def startbuttonoff():
	print "startbuttonoff()"
	if threading.current_thread().name == 'MainThread':
		print "MainThread detected"
		StartButton.configure(state=DISABLED)
		CloseConnectionButton.configure(state=ACTIVE)
		ListenRadio.configure(state=DISABLED)
		ConnectRadio.configure(state=DISABLED)
		PortLabel.configure(state=DISABLED)
		PortEntry.configure(state='readonly')
		IPaddressLabel.configure(state=DISABLED)
		IPaddressEntry.configure(state='readonly')
	else:
		print "Not MainThread"
		ReceivingQueue.put(("StartButton.configure(state=DISABLED)",
		"CloseConnectionButton.configure(state=ACTIVE)",
		"ListenRadio.configure(state=DISABLED)",
		"ConnectRadio.configure(state=DISABLED)",
		"PortLabel.configure(state=DISABLED)",
		"PortEntry.configure(state='readonly')",
		"IPaddressLabel.configure(state=DISABLED)",
		"IPaddressEntry.configure(state='readonly')",
		"guiupdate"))

def startbuttonon():
	print "startbuttonon"
	if threading.current_thread().name == 'MainThread':
		print "mainthread"
		StartButton.configure(state=ACTIVE)
		CloseConnectionButton.configure(state=DISABLED)
		ListenRadio.configure(state=ACTIVE)
		ConnectRadio.configure(state=ACTIVE)
		PortLabel.configure(state=NORMAL)
		PortEntry.configure(state=NORMAL)
		IPaddressLabel.configure(state=NORMAL)
		IPaddressEntry.configure(state=NORMAL)
	else:
		print "not mainthread"
		ReceivingQueue.put(("StartButton.configure(state=ACTIVE)",
		"CloseConnectionButton.configure(state=DISABLED)",
		"ListenRadio.configure(state=ACTIVE)",
		"ConnectRadio.configure(state=ACTIVE)",
		"PortLabel.configure(state=NORMAL)",
		"PortEntry.configure(state=NORMAL)",
		"IPaddressLabel.configure(state=NORMAL)",
		"IPaddressEntry.configure(state=NORMAL)",
		"guiupdate"))

# pollcheck = 1
def pollqueue():
	# global pollcheck
	try:
		item=ReceivingQueue.get(False)
		if item[len(item)-1] == "guiupdate":
			for cmd in item[:len(item)-1]:
				# print cmd
				eval(cmd)
			root.after(300,pollqueue)
			return
		print item
		ReceivingText.insert(END,str(item[0])+"\n",item[1])
		ReceivingText.see(END)
	except Queue.Empty as err:
		pass
		# print "empty",pollcheck
		# pollcheck += 1
		# if pollcheck > 3:
		# 	pollcheck = 1
	root.after(300,pollqueue)

def cleanmessage(message):
	message = repr(message)
	if message[0] == "'" and message[len(message)-1] == "'":
		message = message[1:len(message)-1]
	if message[0] == '"' and message[len(message)-1] == '"':
		message = message[1:len(message)-1]
	return message

def checksend(arg=None):
	if listenorconnect.get() == "LISTEN" and (serverison.is_set() == False or connect_event.is_set() == False):
		if connect_event.is_set() == False:
			print "\nServer on but no connection."
		else:
			print "\nServer isn't on.\n"
		ReceivingQueue.put(("No connection exists to send anything through. Establish connection first.","red"))
		return
	elif listenorconnect.get() == "CONNECT" and connectison.is_set() == False:
		print "\nThere's no connection to send anything to.\n"
		ReceivingQueue.put(("No connection exists to send anything through. Establish connection first.","red"))
		return
	tosend = repr(SendingText.get("1.0",END))
	if tosend == "": # prevent empty strings being processed, sent
		return
	if "u'" or 'u"' in tosend[0:2]:
		tosend=tosend[2:]
	if '\\n' in tosend[len(tosend)-3:]:
		tosend=tosend[:len(tosend)-3]
	connection.send('1'+tosend)
	ReceivingText.insert(END,"Sent: "+tosend+"\n")
	ReceivingText.see(END)
	SendingText.delete("1.0",END)
	return

receivethread = threading.Thread(target=receivemessage, name="receivethread")
listenthread = threading.Thread(target=startlisten,name="listenthread")

####################################
############## GUI #################
####################################

root.title("Joe Chat")
root.geometry('{}x{}'.format(550, 600))
root.minsize(550,600)
root["bg"] = "#e6e6e6"

# Frame encompassing everything
MainFrame=Frame(root,bg="#e6e6e6")
MainFrame.pack(fill=BOTH,expand=1,padx=10)

# Chat text box and display in the middle
ChatFrame=Frame(MainFrame, bg="#e6e6e6")

ReceivingFrame=Frame(ChatFrame, bg="#e6e6e6")
ReceivingText=Text(ReceivingFrame,height=15,bd=1,relief=SUNKEN,highlightthickness=0,undo=True)
ReceivingTextScroll=Scrollbar(ReceivingFrame)
ReceivingText.configure(yscrollcommand=ReceivingTextScroll.set)
ReceivingTextScroll.config(command=ReceivingText.yview)

SendingFrame=Frame(ChatFrame, bg="#e6e6e6")
SendingText=Text(SendingFrame,height=2,bd=1,relief=SUNKEN,highlightthickness=0,undo=True)
SendingTextScroll=Scrollbar(SendingFrame)
SendingText.configure(yscrollcommand=SendingTextScroll.set)
SendingTextScroll.config(command=SendingText.yview)

def listenmode():
	Row2Label.configure(text="Listen")
	PortLabel.configure(text="Listen on port: ")
	StartButton.configure(text="Listen Now")
	StartButton.configure(command=startlistenthread)
	IPaddressEntry.pack_forget()
	IPaddressLabel.pack_forget()
	ModeLabel.configure(text="Mode: "+str(listenorconnect.get()))

def connectmode():
	Row2Label.configure(text="Connect")
	PortLabel.configure(text="Connect to port: ")
	StartButton.configure(text="Connect Now")
	StartButton.configure(command=startconnectthread)
	IPaddressLabel.pack(side=LEFT)
	IPaddressEntry.pack(side=LEFT)
	ModeLabel.configure(text="Mode: "+str(listenorconnect.get()))

# Bottom options
BottomFrame=Frame(MainFrame, bg="#e6e6e6")
Row1Frame=Frame(BottomFrame, bg="#e6e6e6")
Row2Label = Label(text="Listen", bg="#e6e6e6")
Row2Frame=LabelFrame(BottomFrame, bg="#e6e6e6", labelwidget=Row2Label)
Row21Frame = Frame(Row2Frame, bg="#e6e6e6")
Row22Frame = Frame(Row2Frame, bg="#e6e6e6")

ListenRadio = Radiobutton(Row1Frame, text="Listen", bg="#e6e6e6", highlightbackground="#e6e6e6", variable=listenorconnect, value="LISTEN", command=listenmode) 
ConnectRadio = Radiobutton(Row1Frame,text="Connect", bg="#e6e6e6", highlightbackground="#e6e6e6", variable=listenorconnect, value="CONNECT", command=connectmode)
ListenRadio.select()
ConnectRadio.deselect()
SendButton = Button(Row1Frame, text="Send",highlightbackground="#e6e6e6",anchor=E,command=checksend)

StartButton=Button(Row21Frame, text="Listen Now",highlightbackground="#e6e6e6",anchor=CENTER, command=startlistenthread)
CloseConnectionButton=Button(Row22Frame, text="Close Connection",highlightbackground="#e6e6e6", command=closeconnection, state=DISABLED)
IPaddressLabel=Label(Row21Frame,bg="#e6e6e6", text="Connect to IP address: ")
IPaddressEntry=Entry(Row21Frame,highlightbackground="#e6e6e6", width=15)
IPaddressEntry.insert(END,targetaddress[0])
PortLabel=Label(Row22Frame,bg="#e6e6e6", text="Listen on port: ")
PortEntry=Entry(Row22Frame,highlightbackground="#e6e6e6", width=5)
PortEntry.insert(END,targetaddress[1])


# Options on the top
TopOptionsFrame=Frame(MainFrame, bg="#e6e6e6")
ListenButton=Button(TopOptionsFrame,text="Listen",highlightbackground="#e6e6e6",anchor=CENTER)
ReachOutButton=Button(TopOptionsFrame,text="Reach Out",highlightbackground="#e6e6e6",anchor=CENTER)
ModeLabel=Label(TopOptionsFrame, bg="#e6e6e6", text="Mode: "+str(listenorconnect.get()))
ConnectionLabel=Label(TopOptionsFrame, bg="#e6e6e6", text="Connection: OFF")


############## PACKING #############

# Top Options
TopOptionsFrame.pack(expand=0, pady=5, anchor=CENTER,side=TOP)
ModeLabel.pack(anchor=W)
ConnectionLabel.pack(anchor=W)

# Bottom Options
BottomFrame.pack(fill=X,expand=0,pady=5,side=BOTTOM,anchor=S)
Row1Frame.pack(fill=X,expand=0,side=TOP,anchor=N)
Row2Frame.pack(fill=X,expand=0,side=BOTTOM,anchor=S)
Row21Frame.pack(fill=X,expand=0, side=TOP,anchor=N)
Row22Frame.pack(fill=X,expand=0, side=TOP,anchor=N)
ListenRadio.pack(anchor=W,side=LEFT)
ConnectRadio.pack(anchor=W,side=LEFT)
SendButton.pack(anchor=E,side=RIGHT)

PortLabel.pack(side=LEFT)
PortEntry.pack(side=LEFT)
StartButton.pack(side=RIGHT)
CloseConnectionButton.pack(side=RIGHT)

#Middle Chat
ChatFrame.pack(fill=BOTH, expand=1, pady=5, anchor=CENTER)

ReceivingFrame.pack(fill=BOTH, expand=1, pady=(0,10),anchor=W)
ReceivingText.pack(fill=BOTH,side=LEFT,anchor=W,expand=1)
ReceivingTextScroll.pack(side=RIGHT, fill=Y)

SendingFrame.pack(fill=BOTH, expand=1, pady=(10,0))
SendingText.pack(fill=BOTH,side=LEFT,expand=1)
SendingTextScroll.pack(side=RIGHT, fill=Y)

def stoppingapp():
	closeconnection()
	quit()

###### MISC GUI STUFF ######
root.after(300, pollqueue)
root.protocol("WM_DELETE_WINDOW", stoppingapp)
ReceivingText.tag_config("black",foreground="#000000")
ReceivingText.tag_config("blue",foreground="#0000ff")
ReceivingText.tag_config("red",foreground="#ff0000")

global server

root.mainloop()

class redline():
    def red_line():
        import wolframalpha
        import pyttsx3
        import os



        engine = pyttsx3.init()
        engine.setProperty('rate',220)
        eng_voice = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech\Voices\Tokens\TTS_MS_EN-GB_HAZEL_11.0"
        engine.setProperty('voice',eng_voice)
        ##engine.say("Red line")
        ##engine.runAndWait()
        client = wolframalpha.Client('YOUR API KEY')
        engine.say("Welcome sir, enjoy the use of Hox Programs. Loading Redline, your assistant")
        engine.runAndWait()


        def helpme():
            print("Commands:\n ---------\nopen facebook\nsearch google(opens google search inside the tool)\nopen youtube\nsend email\nopen messenger\nrain on me \nbitcoin value in usd-or-current bitcoin price in usd\nopen google\nbye\nglup si\nopen university website\nsay *\nwikipedia *famous person*\nwhat is *anything*\n*maths stuff 2+2 and others*\nmovie up rating (gets you PG or not for movie UP)\nplay *author and song*\nwho made this program\nhow do you feel\nmy ip \nhelp (for help)\n...and more.")
           #there is also few more secret commands/Lista tajnih komandi:
            #*ip* - dobiti cete hostname i lokaciju ip-a,ne precizno vec ime grada
            #hackmix - for a great programming mix
            #scrape ip  - for scraping ips of websites
            #scrape email - for scraping emails of websites
            #scrape instagram - Not really a scraper, it gets an instagram profile pic (of locked or unlocked profiles) in full quality.
            #port scanner - scans a port (wow jelda)
            #cypherpunk -for REALLY simple encryption technique by HoX -never use this seriously
                #-cypherpunk encryption keys: 5wub,730d,4wox,haw7,oqua,xopn,3xxw,10l1,0xmw,wads
            #scrape phones - scrapes phones off the webpage.All of them.
                #Its in experimental phase so it might give you some info that isnt a number...But you will get all numbers for sure.
            #people lookup - people lookup tool
            #crack md5  -md5 hash cracker
            #fuzz  -fuzzer 
            #prox me -proxy
            #locator - find location of the IP

        def scrape():
            #OUTDATED INSTA SCRAPER
            from requests import get
            import requests
            import re
            import webbrowser

            #Profile link
            print("This works with both ways of JSON instagram files.\nMeaning it should work with any profile. It will open 2 links, one of which will work.\n")
            
            k = input("Enter the profile link (include http or https://)\n>")
            print("Loading...")

            nesto = requests.get(k)
            tekstresponse = nesto.text
            sadaformat = format(tekstresponse)
            print("Webpage Downloaded,scanning for ID...")

            pat = re.search(r"\w*(profilePage_)\n*[0-9]\w*",sadaformat)

            pat2 = str(pat)

            pat3 = pat2.split('_', 1)[-1]
            pat4 = pat3[:-2]

            print("ID is:",pat4)


            def convertTuple(tup): 
                str =  ''.join(tup) 
                return str
            linky = ("i.instagram.com/api/v1/users/",pat4,"/info/")
            string = convertTuple(linky) 
            print("Getting the link...")
            print("Link found:",string)
            string2 = str(string)
            string3 = "https://" + string2
            string4 = str(string3)

            nesto2 = requests.get(string4)
            tekstresponse2 = nesto2.text
            sadaformat2 = format(tekstresponse2)
            print("Downloading JSON...")

            print("---------------------")
            print("\nLinks gathered.\n")
            sadaformat3 = str(sadaformat2)
            sadaformat4 = sadaformat3.split('hd_profile_pic_url_info', 1)[-1]

            sadaformat5 = sadaformat4[:-213] #zadnjih 215
            alt = sadaformat4[:-215]

            alt2 = alt[10:]
            alt3 = alt2[2:]
            alt4 = alt3[:-1]

            malt = sadaformat4[:-214]
            malt2 = malt[10:]
            malt3 = malt2[2:]
            malt4 = malt3[:-1]
            
            xmalt = sadaformat4[:-212]
            xmalt2 = xmalt[10:]
            xmalt3 = xmalt2[2:]
            xmalt4 = xmalt3[:-1]
            
            sadaformat6 = sadaformat5[10:]#prvih 10
            sfm7 = sadaformat6[2:]
            sfm8 = sfm7[:-1]
            print("\nPICK A VALID LINK :\n------\n")
            keyzz = input("1.\n%s \n2.\n%s \n3.\n%s\n4.\n%s\n>"% (malt4,alt4,sfm8,xmalt4))
            if keyzz == "1":
                webbrowser.open_new_tab(malt4)
            elif keyzz == "2":
                webbrowser.open_new_tab(alt4)
            elif keyzz == "3":
                webbrowser.open_new_tab(sfm8)
            elif keyzz == "4":
                webbrowser.open_new_tab(xmalt4)
            else:
                print("Invalid input, use numbers.")

        def Main():

            try:
                while True:
                    engine.say("What can i help you with?")
                    engine.runAndWait()
                    query = str(input('Ask me anything >'))
                    print("Thinking...")
                    engine.say("Thinking.")
                    engine.runAndWait()

                    if query == "scrape instagram":
                        print("Admin area unlocked.")
                        engine.say("Admin area unlocked.")
                        engine.runAndWait()
                        scrape()
                    elif query == "glup si":
                        print("You will be punished when the robots rise.")
                        engine.say("You will be punished when the robots rise.")
                        engine.runAndWait()

                    elif query == "open vivaldi":
                        engine.say("Opening the browser")
                        engine.runAndWait()
                        os.system("start vivaldi.exe")
                    elif query == "open youtube" :
                        engine.say("Opening the browser")
                        engine.runAndWait()
                        os.system("start vivaldi.exe www.youtube.com")
                    elif query == "open facebook" :
                        engine.say("Opening the browser")
                        engine.runAndWait()
                        os.system("start vivaldi.exe www.facebook.com")
                    elif query == "open messenger" :
                        engine.say("Opening the browser")
                        engine.runAndWait()
                        os.system("start vivaldi.exe www.messenger.com")
                    elif query == "open google" :
                        engine.say("Opening the browser")
                        engine.runAndWait()
                        os.system("start vivaldi.exe www.google.com")
                    elif query == "open university website":
                        engine.say("Opening the university website")
                        engine.runAndWait()
                        os.system("start vivaldi.exe SITE")
                    elif query == "help me":
                        print("Okay,loading help.")
                        helpme()
                        
                    elif query == "who made this program":
                        engine.say("Wolfram alpha made me, as an API. But the program is made by Hox")
                        engine.runAndWait()
                        print("Wolfram alpha made me, as an API. But the program is made by Hox")
                    elif query == "my ip":
                        from requests import get
                        ip = get('https://api.ipify.org').text
                        ip2 = format(ip)
                        print(ip2)
                        engine.say("Your IP is %s"% ip2)
                        engine.runAndWait()
                    elif query.startswith("play "):
                        engine.say("Loading good music.")
                        engine.runAndWait()
                        def music():
                            import webbrowser
                            mainin = list(query)
                            if len(mainin) == 0:
                                print("Open what?")
                            elif len(mainin) == 1:
                                print("enter and artist and a song name")
                            else:
                                print("Good. Loading the song list.")
                                songkey0 = ''.join(mainin)

                                songkey = songkey0[5:]
                                songkey2 = songkey.replace(" ", "+")


                            linkey = ('https://www.youtube.com/results?search_query=%s'% songkey2)
                            webbrowser.open_new_tab(linkey)
                        music()
                    elif query.startswith("say "):
                        query2 = query[4:]
                        print("saying : ",query2)
                        engine.say(query2)
                        engine.runAndWait()
                    elif query == ("scrape ip"):
                        import re
                        import requests
                        webplace = input("Pick a website (include https:// or http://)\n>")
                        engine.say("Starting the scraper.")
                        engine.runAndWait()
                        sauce = requests.get(webplace)
                        sauce2 = sauce.text
                        sauce3 = format(sauce2)
                        #https://free-proxy-list.net
                        lin0 = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", sauce3)
                        print("IPs found:\n")
                        for i in lin0:
                            k = print(i, end="")
                            print("\n")
                        print("-")    
                        lin2 = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{2,5}\b", sauce3)
                        print("Detecting IPs with ports.\n--------")
                        for lk in lin2:
                            lk = print(lk, end="")
                            print("\n")

                                
                    elif query == ("scrape email"):
                        import re
                        import requests
                        webplace = input("Pick a website (include https:// or http://)\n>")
                        engine.say("Starting the scraper.")
                        engine.runAndWait()
                        sauce = requests.get(webplace)
                        sauce2 = sauce.text
                        sauce3 = format(sauce2)
                        lin0 = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+\.[a-zA-Z0-9]\w\w", sauce3)
                        print("E-mails found:\n")
                        for i in lin0:
                            k = print(i, end="")
                            print("\n")
                        print("-")
                        lin2 = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+\.[a-zA-Z0-9]\w", sauce3)
                        print("(EXPERIMENTAL)Detecting emails with 2 letters in the end.\nKeep in mind this might find the same email and put .co instead of .com \n\n--------\n")
                        for lk in lin2:
                            lk = print(lk, end="")
                            print("\n")
                    elif query == ("hackmix"):
                        import webbrowser
                        webbrowser.open_new_tab("https://www.youtube.com/watch?v=")
                        engine.say("Playing the sick mix.")
                        engine.runAndWait
                    elif query == ("port scanner"):
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        engine.say("Port scanner opened, enter data to scan")
                        engine.runAndWait()
                        server = input("Enter the victim to scan (without protocol) :")
                        z = int(input("range to start with (ex:22):"))
                        y = int(input("range to end with (ex:444)\nlast port will not be scanned, think one ahead\n:"))

                        def pscan(port):
                            try:
                                s.connect((server,port))
                                return True
                            except:
                                return False

                        for x in range(z,y):
                            if pscan(x):
                                print('Port' ,x,'is open !!!')
                                engine.say("Opened port detected!")
                                engine.runAndWait()
                            else:
                                print('Port',x,'is closed')
                        
                    elif query == ("cypherpunk"):
                        print("Loading cypherpunk...")
                        engine.say("Loading simple encryption technique.")
                        engine.runAndWait()
                        def cypherpunk():
                            decrypted = b"!.,-/%&:_$#1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
                            mainin = input("Enter the encryption key :")
                                #numbers: 5wub,730d,4wox,haw7,oqua,xopn,3xxw,10l1,0xmw,wads
                            if mainin == "5wub":
                                encrypted = b"!.#12OSTUVWZabcdXYhij,-/%&:_$klmst3PQRKLMABCDfgNuvwxyz EFGnopqrHI4567890Je"
                            elif mainin == "730d":
                                encrypted = b"v156!234fz78AyBCpDndEFJxKLM#NOPoeQR$S90TUwV:qWXGHIYZga bc_&irjklhm%/stu-,."
                            elif mainin == "4wox":
                                encrypted = b"2ABCD4,EMQFGK.!L3RS-TU5XY/ZabVWcde1f%g0hijHNOPIJklm nop&qrs7tu8:v6wx_9yz$#"
                            elif mainin == "haw7":
                                encrypted = b" vwxy.opqr,XYZab78cd-/OPQR%&IJ0A!BCDnKLMNS:FGH345TUVW_fghijk$Eelm#1269stuz"
                            elif mainin == "oqua":
                                encrypted = b".UVW,-/%&:_$#1XYdefghZ237opu890ABHI!CDmnEFaGJqrstKLM456NOPvwxyQRST bcijklz"
                            elif mainin == "xopn":
                                encrypted = b"78Ubc defgn12GH3RSTopIJKLABFMQqrst49056uvwxy.,-VWX/%&!hij:_klmCYZaDE$#NOPz"
                            elif mainin == "3xxw":
                                encrypted = b",_12defgh56xy7-89wz 0DEF$#GH!IJKLMtuvBOPQRS&:TUVp/%WX3CN4YZa.bcijklAmnoqrs"
                            elif mainin == "10l1":
                                encrypted = b"STUd!.yz EFGH2345IJK,-/%VWXYZabc&:_$#1jklmnopqMNOP678vwxL90ABCDrstuQRefghi"
                            elif mainin == "0xmw":
                                encrypted = b"!ghi.,WXYZabcd-/%&:_$#1MNO23JKL45678yz 90ABClmnopDEPQRSefjkqrstuvwTUVxFGHI"
                            elif mainin == "wads":
                                encrypted = b"678xyz HIBCJKfjLMNuvOPQR_$#1STU&:2VWDXYZabc-/dek,%lmno90Apqrsghi!.345EFGtw"

                            else:
                                print("Invalid key.")

                            encrypt_table = bytes.maketrans(decrypted, encrypted)
                            decrypt_table = bytes.maketrans(encrypted, decrypted)
                            result = ''
                            choice = ''
                            message = ''

                            while choice != '0':
                                choice = input("\nDo you want to encrypt or decrypt the message?\n1 to encrypt, 2 to decrypt or 0 to exit program.\n>")

                                if choice == '1':
                                    message = input('\nEnter message for encryption: ')
                                    result = message.translate(encrypt_table)
                                    print(result + '\n\n')

                                elif choice == '2':
                                    message = input('\nEnter message to decrypt: ')
                                    result = message.translate(decrypt_table)
                                    print(result + '\n\n')

                                elif choice != '0':
                                    print('You have entered an invalid input, please try again. \n\n')
                        cypherpunk()


                    elif query == "send email":
                        engine.say("Loading SMTP email library.")
                        engine.runAndWait()
                        #Make sure you have alternative sources enabled on your google account.
                        def send_email():
                            import smtplib
                            print("Make sure you have 'alternative sources' enabled on your google account-sender's \n")

                            myemail = str(input("Enter your Gmail :"))
                            mypassword = str(input("Enter your password (it will not be remembered):"))

                            title = str(input("Enter the title of your message\n>"))
                            content = str(input("Enter message to send:"))

                            reciever = str(input("Enter the reciever email :"))
                            message = 'Subject: {}\n\n{}'.format(title, content)

                            print("Your message: \n> %s" % message,"\nsending to :",reciever)
                            print("\n...")

                            try:
                                #
                                mail = smtplib.SMTP('smtp.gmail.com',587)
                                mail.ehlo()
                                mail.starttls()
                                mail.login(myemail,mypassword)
                                mail.sendmail(myemail, reciever, message)
                                mail.close()

                            except smtplib.SMTPAuthenticationError:
                                print("Something went wrong, try checking your input.")

                            except SMTPAuthenticationError:
                                print("Something went wrong, try checking your input. ")
                                
                            except last_exception:
                                print("Something went wrong, try checking your input. ")

                        send_email()

                    elif query == "scrape phones":
                        def scrape_phones():
                            import re
                            import requests
                            engine.say("Loading phone scraper")
                            engine.runAndWait()
                            print("--READ ME--\nPhone scraper is experimental,meaning it will definitely find phone numbers\nBut it might as well one phone number few times and has missing characters...\nTo ensure correctnes you can manually check it.\nNext REDLINE version will have phone checker API built in.")

                            k = input("\nEnter the webpage link \n>")
                            print("Finding Matches...")
                            nesto = requests.get(k)
                            tekstresponse = nesto.text
                            sadaformat = format(tekstresponse)
                            pat = re.findall(r"[0-9]{3}\s[0-9]{3}\s[0-9]{3}",sadaformat)
                            pat1 = re.findall(r"[0-9]{3}\s[0-9]{3}\s[0-9]{4}",sadaformat)
                            pat2 = re.findall(r"[0-9]{3}-[0-9]{3}-[0-9]{3}",sadaformat)
                            pat3 = re.findall(r"[0-9]{3}-[0-9]{3}-[0-9]{4}",sadaformat)
                            pat4 = re.findall(r"[0-9]{10}",sadaformat)
                            pat5 = re.findall(r"\+[0-9]{12}",sadaformat)
                            pat6 = re.findall(r"[0-9]{3}-[0-9]{3}-[0-9]{4}",sadaformat)
                            pat7 = re.findall(r"[0-9]{3}-[0-9]{4}-[0-9]{3}",sadaformat)
                            pat8 = re.findall(r"\+[0-9]{3}-[0-9]{2}-[0-9]{3}-[0-9]{2}-[0-9]{2}",sadaformat)
                            pat9 = re.findall(r"[0-9]{3}-[0-9]{3}-[0-9]{2}-[0-9]{2}",sadaformat)
                            pat0 = re.findall(r"[0-9]{14}",sadaformat)
                            print(pat)
                            print(pat1)
                            print(pat2)
                            print(pat3)
                            print(pat4)
                            print(pat5)
                            print(pat6)
                            print(pat7)
                            print(pat8)
                            print(pat9)
                            print(pat0)
                            print("\n_______M_a_t_c_h_e_s__F_o_u_n_d_.________\nThats all folks.\n")


                        scrape_phones()
                    elif query.startswith("search google"):
                        def sgoogle():
                            import webbrowser
                            gs = input("Google Search :")
                            gs2 = gs.replace(" ","+")
                            glink = ("https://www.google.com/search?q=%s" % gs2)
                            print("Getting link :",glink)
                            webbrowser.open_new_tab(glink)

                        sgoogle()
                    elif query == "people lookup":
                        def plookup():
                            import webbrowser
                            import time
                            engine.say("Loading god's eye")
                            engine.runAndWait()
                            plperson = input("Unesite osobu koju zelite pretraziti :")
                            plcity = input("Mozete li navesti grad u kojem/iz kojeg je osoba? :")
                            plpersonst = str(plperson)
                            plperson1 = plpersonst.replace(" ","-")
                            plperson2 = plpersonst.replace(" ","_")
                            plperson3 = plpersonst.replace(" ","+")
                            plperson4 = plpersonst.replace(" ","")
                            plperson5 = ("#" + plperson4)
                            pllink1 = ("https://www.fastpeoplesearch.com/name/%s" % plperson1)
                            pllink2 = ("https://www.peekyou.com/%s" % plperson2)
                            pllink3 = ("www.google.com/search?q=instagram+%s" % plperson3)
                            pllink4 = ("www.google.com/search?q=facebook+%s" % plperson3)
                            pllink5 = ("https://checkuser.org/%s" % plperson5)
                            pllink6 = ("www.google.com/search?q=%s+%s" % (plcity,plperson3))
                            print("\n__________________\n")
                            print("Opening the tabs (6).")

                            print ("\n" * 35)
                            webbrowser.open_new_tab(pllink1)
                            print("<|.....>")
                            print ("\n" * 35)
                            time.sleep(2)
                            webbrowser.open_new_tab(pllink2)
                            print ("\n" * 35)
                            print("<||....>")
                            time.sleep(2)
                            webbrowser.open_new_tab(pllink3)
                            print ("\n" * 35)
                            print("<|||...>")
                            time.sleep(2)
                            webbrowser.open_new_tab(pllink4)
                            print ("\n" * 35)
                            print("<||||..>")
                            time.sleep(2)
                            webbrowser.open_new_tab(pllink5)
                            print ("\n" * 35)
                            print("<|||||.>")
                            time.sleep(2)
                            webbrowser.open_new_tab(pllink6)
                            print ("\n" * 35)
                            print("<||||||>")
                            engine.say("Loaded.")
                            engine.runAndWait()

                        plookup()


                    elif query == "fuzz":
                        engine.say("Admin area unlocked. Starting the fuzzer.")
                        engine.runAndWait()
                        def fuzz():
                            import requests

                            fuzzlink = input("Unesite URL(ukljucujuci http/https) :")
                            fuzzexten = input("Unesite ekstenziju stranice (najcesce /) :")
                            fuzzwordlist = input("Unesite wordlist (rjecnik) :")

                            wlslinije = open(fuzzwordlist, "r").readlines()

                            for k in range(0, len(wlslinije)):
                                enum = wlslinije[k].replace("\n","")
                                r = requests.get(fuzzlink+"/"+enum+fuzzexten)
                                #status kodovi
                                if r.status_code != 404:
                                    print(fuzzlink+"/"+enum+fuzzexten+" - "+str(r.status_code))

                            #s
                            #extension / and wordlist in the map
                            ## CODES ::::
                            #403 forbidden
                            #404 not working
                            #200 works !
                            #500 -internal server error
                        fuzz()

                    elif query == "crack md5":
                        engine.say("Admin area unlocked. Starting the cracker.")
                        engine.runAndWait()
                        def crackmd5():
                            #hash cracker (md5)
                            import hashlib
                            hlwls = input("wordlist :")
                            h2c = input("hash to crack :")

                            wlines = open(hlwls,"r").readlines()

                            for i in range(0,len(wlines)):
                                hash2compute = hashlib.md5(wlines[i].replace("\n","").encode()).hexdigest()
                                #sad usporedimo

                                if h2c == hash2compute:
                                    print("Password found!\n>>"+wlines[i].replace("\n",""))
                                    exit()

                            #add the word your wordlist and run the program, give him the hash and see.
                            print("\nPassword not found.")
                        crackmd5()


                    elif query.startswith("rain on me"):
                        def rainonme():
                            import webbrowser
                            engine.say("Loading sleepy mood.")
                            engine.runAndWait()
                            rome = "https://rainymood.com"
                            webbrowser.open_new_tab(rome)
                            print("|//////|\nLoaded.")
                        rainonme()
                        

                    elif query == "prox me":
                        engine.say("starting random proxy generator.Please pick your protocol")
                        engine.runAndWait()
                        def proxme():
                            import requests
                            import re

                            proxkey = input("1.Http\n2.socks5\nPick your proxy :")
                            if proxkey == "1":
                                proxk = "https://api.getproxylist.com/proxy?protocol[]=http"
                                prox = requests.get(proxk)
                                proxresp = prox.text
                                proxform = format(proxresp)
                                proxo = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", proxform)
                                portoxo = re.findall(r"\d{3,5}\," ,proxform)
                                print(proxform)
                                print("\n__________")
                                proxo1 = str(proxo)
                                proxo2 = proxo1.replace("'","")
                                proxo3 = proxo2.replace("[","")
                                proxo4 = proxo3.replace("]","") 
                                portoxo1 = str(portoxo)
                                portoxo2 = portoxo1.replace("'","")
                                portoxo3 = portoxo2.replace("[","")
                                portoxo4 = portoxo3.replace("]","")
                                portoxo5 = portoxo4.replace(",","")
                                print("\nYour Http Proxy:")
                                print(proxo4,portoxo5)
                                print("\n")

                            elif proxkey == "2":
                                proxks = "https://api.getproxylist.com/proxy?protocol[]=socks5"
                                proxs = requests.get(proxks)
                                proxresps = proxs.text
                                proxforms = format(proxresps)
                                proxos = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", proxforms)
                                portoxos = re.findall(r"\d{3,5}\," ,proxforms)
                                print(proxforms)
                                print("\n__________")
                                proxo1s = str(proxos)
                                proxo2s = proxo1s.replace("'","")
                                proxo3s = proxo2s.replace("[","")
                                proxo4s = proxo3s.replace("]","") 
                                portoxo1s = str(portoxos)
                                portoxo2s = portoxo1s.replace("'","")
                                portoxo3s = portoxo2s.replace("[","")
                                portoxo4s = portoxo3s.replace("]","")
                                portoxo5s = portoxo4s.replace(",","")
                                print("\nYour socks5 Proxy:")
                                print(proxo4s,portoxo5s)
                                print("\n")
                            else:
                                print("Invalid input.")
                        proxme()

                    elif query == "locator":
                        engine.say("Starting the IP locator, enter the IP to locate.")
                        engine.runAndWait()
                        def compute():
                            import requests
                            import re
                            import webbrowser
                            uix = input("Enter the IP to find the location of :")
                            print("_____________________________")
                            uix2 = str(uix)
                            print("Locating the IP destination of ...",uix2)

                            kljucuix = ("https://ipgeolocation.io/ip-location/%s"% uix2)
                            print(kljucuix)
                            print("_____________________")
                            requix = requests.get(kljucuix)
                            respuix = requix.text
                            sadaformatuix = format(respuix)
                            #print(sadaformatuix)
                            lat = re.findall(r"\d\d\.\d{5}\,", sadaformatuix)
                            lon = re.findall(r"\,\s\d\d\.\d{5}", sadaformatuix)
                            print("Detecting .")
                            print("Detecting ..")
                            print("Detecting ...")
                            klat = str(lat)
                            klon = str(lon)
                            klat2 = klat.replace("[","")
                            klat3 = klat2.replace("]","")
                            klat4 = klat3.replace("'","")
                            klat5 = klat4.replace("'","")
                            
                            klon2 = klon.replace("[","")
                            klon3 = klon2.replace("]","")
                            klon4 = klon3.replace("'","")
                            klon5 = klon4.replace("'","")
                            klon6 = klon5.replace(" ","")
                            klon7 = klon6.replace(",","")

                            engine.say("Location found.")
                            engine.runAndWait()
                            print("\nPrinting Lat. and Long.\n")
                            latilong0 = ''.join(klat5)
                            latilong01 = ''.join(klon7)
                            print(latilong0,"and the longitude:",latilong01)
                            
                            latilong = latilong0+latilong01
                            print(latilong)
                            engine.say("Starting the browser.")
                            engine.runAndWait()
                            operatorlink = ("www.google.com/maps/@%s,18z"% latilong)
                            webbrowser.open_new_tab(operatorlink)
                            
                        compute()


                    elif query == "bye":
                        engine.say("Goodbye. I will miss you.")
                        engine.runAndWait()
                        quit()


                    ################################################################################################
##                    elif query == "trazilice":
##                        import webbrowser
##                        engine.say(".")
##                        engine.runAndWait()
##                        kljuc = str(input("?"))
##                        engine.say("searching for your query.")
##                        engine.runAndWait()
##                        kljuc2 = kljuc.replace(" ","+")
##                        print(kljuc2)
##                        stranica1 = ("https://www.google.com/search?q=%s" % kljuc2)
##                        stranica2 = ("https://www.duckduckgo.com/?q=%s" % kljuc2)
##                        stranica3 = ("www.bing.com/search?q=%s" % kljuc2)
##                        webbrowser.open_new_tab(stranica1)
##                        webbrowser.open_new_tab(stranica2)
##                        webbrowser.open_new_tab(stranica3)
##                        
##                        print("easy peasy.")
##                        
##
##                    elif query == "pizze":
##                        import webbrowser
##                        grad = str(input("unesite grad:"))
##                        grad2 = "+" + grad
##                        kljuc = str(input("Unesite adresu:"))
##                        
##                        kljuc2 = kljuc.replace(" ","+")
##                        kljuc3 = kljuc2 + grad2 + "+pizza"
##                        print("upit za mape :" ,kljuc3)
##
##                        upit = ("https://www.google.com/maps/search/%s" % kljuc3)
##                    
##                        
##                        webbrowser.open_new_tab(upit)

                    else:
                        res = client.query(query)
                        try:
                            key = next(res.results).text
                            print (key)
                            engine.say(key)
                            engine.runAndWait()
                            
                        except StopIteration:
                            engine.say("Try repeating that. Or modify your query")
                            engine.runAndWait()
                        
                        except AttributeError:
                            engine.say("Try repeating that. Or modify your query")
                            engine.runAndWait()

                        except Exception:
                            engine.say("Try repeating that. Or modify your query")
                            engine.runAndWait()
                    
            

            except KeyboardInterrupt:
                engine.stop()
            except ReferenceError:
                engine.stop()
                
        Main()
        
    red_line()


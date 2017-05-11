

#---GTK 3 Course -----

'''
class ImgDisplay(Gtk.Window):

    def __init__(self):
        Gtk.Window.__init__(self, title="Image Display")
        self.set_border_width(3)
        self.connect("delete-event", Gtk.main_quit)

        self.box = Gtk.Box(spacing=6)

        self.table = Gtk.Table(3, 2, True)
        self.table.attach(self.box, 0, 2, 0, 2)

        self.add(self.table)
        self.spinner.start()
        self.show_all()

    def update_image(self, data=None):

        image = Gtk.Image()
        image.set_from_file(data)
        self.box.add(image)
        self.box.show_all()

    def link_extract(self, packet,http_packet):

        ret = ""
        if http_packet.find('GET') != -1 and \
        (http_packet.find('.jpg') != -1 or \
        http_packet.find(".png") != -1 or \
        http_packet.find('.jpeg') != -1 or \
        http_packet.find('.gif') != -1):
            ret += "\n".join(packet.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
            return "http://" + str(str(packet[IP].dst) + ret[ret.find("GET")+4:ret.find("HTTP")])
        else:
            return None

    def http_header(self, packet):

        sr = ""
        http_packet=str(packet)
        sr = self.link_extract(packet, http_packet)
        if sr is not None:
            urllib.urlretrieve(sr, "/tmp/img/" + sr[sr.rfind('/')+1:])
            #self.update_image(sr[sr.rfind('/')+1:])
'''

#---------------------
